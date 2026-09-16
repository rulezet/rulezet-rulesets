rule TTP_XOR_WriteProcessMemory_a685 {
  strings:
    $key_a685 = { f1 f7 [2] c3 d5 [2] c5 e0 [2] eb e0 [2] d4 fc }

  condition:
    any of them
}