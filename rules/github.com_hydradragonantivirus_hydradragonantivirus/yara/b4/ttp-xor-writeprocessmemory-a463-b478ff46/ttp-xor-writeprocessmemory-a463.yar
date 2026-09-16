rule TTP_XOR_WriteProcessMemory_a463 {
  strings:
    $key_a463 = { f3 11 [2] c1 33 [2] c7 06 [2] e9 06 [2] d6 1a }

  condition:
    any of them
}