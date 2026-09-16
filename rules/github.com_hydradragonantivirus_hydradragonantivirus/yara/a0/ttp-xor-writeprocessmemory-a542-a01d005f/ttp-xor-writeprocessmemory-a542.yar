rule TTP_XOR_WriteProcessMemory_a542 {
  strings:
    $key_a542 = { f2 30 [2] c0 12 [2] c6 27 [2] e8 27 [2] d7 3b }

  condition:
    any of them
}