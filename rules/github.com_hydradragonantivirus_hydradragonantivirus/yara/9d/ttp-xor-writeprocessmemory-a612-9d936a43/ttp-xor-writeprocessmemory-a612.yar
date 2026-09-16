rule TTP_XOR_WriteProcessMemory_a612 {
  strings:
    $key_a612 = { f1 60 [2] c3 42 [2] c5 77 [2] eb 77 [2] d4 6b }

  condition:
    any of them
}