rule TTP_XOR_WriteProcessMemory_a4d1 {
  strings:
    $key_a4d1 = { f3 a3 [2] c1 81 [2] c7 b4 [2] e9 b4 [2] d6 a8 }

  condition:
    any of them
}