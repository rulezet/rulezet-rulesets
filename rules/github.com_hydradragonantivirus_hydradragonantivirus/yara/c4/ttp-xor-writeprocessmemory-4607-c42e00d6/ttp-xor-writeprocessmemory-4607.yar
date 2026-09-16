rule TTP_XOR_WriteProcessMemory_4607 {
  strings:
    $key_4607 = { 11 75 [2] 23 57 [2] 25 62 [2] 0b 62 [2] 34 7e }

  condition:
    any of them
}