rule TTP_XOR_WriteProcessMemory_a643 {
  strings:
    $key_a643 = { f1 31 [2] c3 13 [2] c5 26 [2] eb 26 [2] d4 3a }

  condition:
    any of them
}