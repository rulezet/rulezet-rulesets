rule TTP_XOR_WriteProcessMemory_a6f6 {
  strings:
    $key_a6f6 = { f1 84 [2] c3 a6 [2] c5 93 [2] eb 93 [2] d4 8f }

  condition:
    any of them
}