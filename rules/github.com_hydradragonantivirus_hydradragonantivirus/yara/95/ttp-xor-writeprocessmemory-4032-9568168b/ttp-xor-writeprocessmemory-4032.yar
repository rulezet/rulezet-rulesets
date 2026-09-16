rule TTP_XOR_WriteProcessMemory_4032 {
  strings:
    $key_4032 = { 17 40 [2] 25 62 [2] 23 57 [2] 0d 57 [2] 32 4b }

  condition:
    any of them
}