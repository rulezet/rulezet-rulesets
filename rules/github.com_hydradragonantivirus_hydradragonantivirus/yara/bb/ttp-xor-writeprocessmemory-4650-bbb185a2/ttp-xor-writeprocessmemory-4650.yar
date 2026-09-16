rule TTP_XOR_WriteProcessMemory_4650 {
  strings:
    $key_4650 = { 11 22 [2] 23 00 [2] 25 35 [2] 0b 35 [2] 34 29 }

  condition:
    any of them
}