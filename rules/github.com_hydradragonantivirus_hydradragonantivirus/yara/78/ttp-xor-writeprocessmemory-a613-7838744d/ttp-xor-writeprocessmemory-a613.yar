rule TTP_XOR_WriteProcessMemory_a613 {
  strings:
    $key_a613 = { f1 61 [2] c3 43 [2] c5 76 [2] eb 76 [2] d4 6a }

  condition:
    any of them
}