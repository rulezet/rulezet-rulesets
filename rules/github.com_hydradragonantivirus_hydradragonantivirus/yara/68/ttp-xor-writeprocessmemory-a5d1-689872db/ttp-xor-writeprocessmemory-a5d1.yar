rule TTP_XOR_WriteProcessMemory_a5d1 {
  strings:
    $key_a5d1 = { f2 a3 [2] c0 81 [2] c6 b4 [2] e8 b4 [2] d7 a8 }

  condition:
    any of them
}