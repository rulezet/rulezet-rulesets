rule TTP_XOR_WriteProcessMemory_a574 {
  strings:
    $key_a574 = { f2 06 [2] c0 24 [2] c6 11 [2] e8 11 [2] d7 0d }

  condition:
    any of them
}