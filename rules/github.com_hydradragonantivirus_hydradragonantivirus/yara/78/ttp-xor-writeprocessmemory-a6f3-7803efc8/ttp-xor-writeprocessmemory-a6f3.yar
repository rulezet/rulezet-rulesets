rule TTP_XOR_WriteProcessMemory_a6f3 {
  strings:
    $key_a6f3 = { f1 81 [2] c3 a3 [2] c5 96 [2] eb 96 [2] d4 8a }

  condition:
    any of them
}