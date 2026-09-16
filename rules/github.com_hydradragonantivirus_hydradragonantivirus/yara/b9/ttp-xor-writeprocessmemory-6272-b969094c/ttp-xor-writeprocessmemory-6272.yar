rule TTP_XOR_WriteProcessMemory_6272 {
  strings:
    $key_6272 = { 35 00 [2] 07 22 [2] 01 17 [2] 2f 17 [2] 10 0b }

  condition:
    any of them
}