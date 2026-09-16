rule TTP_XOR_WriteProcessMemory_4307 {
  strings:
    $key_4307 = { 14 75 [2] 26 57 [2] 20 62 [2] 0e 62 [2] 31 7e }

  condition:
    any of them
}