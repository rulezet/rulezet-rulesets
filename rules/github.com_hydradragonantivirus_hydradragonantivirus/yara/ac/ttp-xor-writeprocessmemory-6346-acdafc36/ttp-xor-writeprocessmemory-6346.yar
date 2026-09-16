rule TTP_XOR_WriteProcessMemory_6346 {
  strings:
    $key_6346 = { 34 34 [2] 06 16 [2] 00 23 [2] 2e 23 [2] 11 3f }

  condition:
    any of them
}