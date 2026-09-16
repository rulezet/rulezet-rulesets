rule TTP_XOR_WriteProcessMemory_a606 {
  strings:
    $key_a606 = { f1 74 [2] c3 56 [2] c5 63 [2] eb 63 [2] d4 7f }

  condition:
    any of them
}