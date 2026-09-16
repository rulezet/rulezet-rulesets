rule TTP_XOR_WriteProcessMemory_a532 {
  strings:
    $key_a532 = { f2 40 [2] c0 62 [2] c6 57 [2] e8 57 [2] d7 4b }

  condition:
    any of them
}