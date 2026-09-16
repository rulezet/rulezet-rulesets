rule TTP_XOR_WriteProcessMemory_a6d0 {
  strings:
    $key_a6d0 = { f1 a2 [2] c3 80 [2] c5 b5 [2] eb b5 [2] d4 a9 }

  condition:
    any of them
}