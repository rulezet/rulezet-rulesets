rule TTP_XOR_WriteProcessMemory_6340 {
  strings:
    $key_6340 = { 34 32 [2] 06 10 [2] 00 25 [2] 2e 25 [2] 11 39 }

  condition:
    any of them
}