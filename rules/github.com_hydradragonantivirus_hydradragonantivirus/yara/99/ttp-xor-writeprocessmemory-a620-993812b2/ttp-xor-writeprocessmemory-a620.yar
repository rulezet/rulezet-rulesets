rule TTP_XOR_WriteProcessMemory_a620 {
  strings:
    $key_a620 = { f1 52 [2] c3 70 [2] c5 45 [2] eb 45 [2] d4 59 }

  condition:
    any of them
}