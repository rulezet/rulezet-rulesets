rule TTP_XOR_WriteProcessMemory_6372 {
  strings:
    $key_6372 = { 34 00 [2] 06 22 [2] 00 17 [2] 2e 17 [2] 11 0b }

  condition:
    any of them
}