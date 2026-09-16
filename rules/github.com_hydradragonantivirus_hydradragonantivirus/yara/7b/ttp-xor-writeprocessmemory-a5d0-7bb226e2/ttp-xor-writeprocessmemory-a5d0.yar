rule TTP_XOR_WriteProcessMemory_a5d0 {
  strings:
    $key_a5d0 = { f2 a2 [2] c0 80 [2] c6 b5 [2] e8 b5 [2] d7 a9 }

  condition:
    any of them
}