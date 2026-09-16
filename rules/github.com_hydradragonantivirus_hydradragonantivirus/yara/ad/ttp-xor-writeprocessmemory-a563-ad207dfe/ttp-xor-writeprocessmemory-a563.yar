rule TTP_XOR_WriteProcessMemory_a563 {
  strings:
    $key_a563 = { f2 11 [2] c0 33 [2] c6 06 [2] e8 06 [2] d7 1a }

  condition:
    any of them
}