rule TTP_XOR_WriteProcessMemory_6361 {
  strings:
    $key_6361 = { 34 13 [2] 06 31 [2] 00 04 [2] 2e 04 [2] 11 18 }

  condition:
    any of them
}