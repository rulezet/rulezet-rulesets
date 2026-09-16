rule TTP_XOR_WriteProcessMemory_a494 {
  strings:
    $key_a494 = { f3 e6 [2] c1 c4 [2] c7 f1 [2] e9 f1 [2] d6 ed }

  condition:
    any of them
}