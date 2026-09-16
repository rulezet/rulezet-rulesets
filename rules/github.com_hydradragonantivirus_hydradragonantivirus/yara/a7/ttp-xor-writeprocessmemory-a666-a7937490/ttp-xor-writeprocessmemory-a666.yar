rule TTP_XOR_WriteProcessMemory_a666 {
  strings:
    $key_a666 = { f1 14 [2] c3 36 [2] c5 03 [2] eb 03 [2] d4 1f }

  condition:
    any of them
}