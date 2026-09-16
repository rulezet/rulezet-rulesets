rule TTP_XOR_WriteProcessMemory_5343 {
  strings:
    $key_5343 = { 04 31 [2] 36 13 [2] 30 26 [2] 1e 26 [2] 21 3a }

  condition:
    any of them
}