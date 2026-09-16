rule TTP_XOR_WriteProcessMemory_a676 {
  strings:
    $key_a676 = { f1 04 [2] c3 26 [2] c5 13 [2] eb 13 [2] d4 0f }

  condition:
    any of them
}