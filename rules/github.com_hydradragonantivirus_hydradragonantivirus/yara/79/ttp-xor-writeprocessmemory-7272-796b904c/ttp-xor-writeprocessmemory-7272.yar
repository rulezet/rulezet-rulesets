rule TTP_XOR_WriteProcessMemory_7272 {
  strings:
    $key_7272 = { 25 00 [2] 17 22 [2] 11 17 [2] 3f 17 [2] 00 0b }

  condition:
    any of them
}