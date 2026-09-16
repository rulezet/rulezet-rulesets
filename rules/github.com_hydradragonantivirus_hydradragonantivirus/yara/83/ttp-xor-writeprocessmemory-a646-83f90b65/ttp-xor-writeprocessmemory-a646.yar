rule TTP_XOR_WriteProcessMemory_a646 {
  strings:
    $key_a646 = { f1 34 [2] c3 16 [2] c5 23 [2] eb 23 [2] d4 3f }

  condition:
    any of them
}