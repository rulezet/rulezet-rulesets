rule TTP_XOR_WriteProcessMemory_a663 {
  strings:
    $key_a663 = { f1 11 [2] c3 33 [2] c5 06 [2] eb 06 [2] d4 1a }

  condition:
    any of them
}