rule TTP_XOR_WriteProcessMemory_a632 {
  strings:
    $key_a632 = { f1 40 [2] c3 62 [2] c5 57 [2] eb 57 [2] d4 4b }

  condition:
    any of them
}