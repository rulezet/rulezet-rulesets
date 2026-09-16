rule TTP_XOR_WriteProcessMemory_6371 {
  strings:
    $key_6371 = { 34 03 [2] 06 21 [2] 00 14 [2] 2e 14 [2] 11 08 }

  condition:
    any of them
}