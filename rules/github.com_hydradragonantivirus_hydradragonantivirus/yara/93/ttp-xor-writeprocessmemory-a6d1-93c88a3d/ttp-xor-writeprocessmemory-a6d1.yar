rule TTP_XOR_WriteProcessMemory_a6d1 {
  strings:
    $key_a6d1 = { f1 a3 [2] c3 81 [2] c5 b4 [2] eb b4 [2] d4 a8 }

  condition:
    any of them
}