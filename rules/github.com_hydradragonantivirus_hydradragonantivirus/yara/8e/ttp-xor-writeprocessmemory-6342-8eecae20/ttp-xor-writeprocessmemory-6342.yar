rule TTP_XOR_WriteProcessMemory_6342 {
  strings:
    $key_6342 = { 34 30 [2] 06 12 [2] 00 27 [2] 2e 27 [2] 11 3b }

  condition:
    any of them
}