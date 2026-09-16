rule TTP_XOR_WriteProcessMemory_a6d6 {
  strings:
    $key_a6d6 = { f1 a4 [2] c3 86 [2] c5 b3 [2] eb b3 [2] d4 af }

  condition:
    any of them
}