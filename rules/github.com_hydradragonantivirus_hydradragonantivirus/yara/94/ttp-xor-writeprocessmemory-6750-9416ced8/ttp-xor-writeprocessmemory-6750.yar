rule TTP_XOR_WriteProcessMemory_6750 {
  strings:
    $key_6750 = { 30 22 [2] 02 00 [2] 04 35 [2] 2a 35 [2] 15 29 }

  condition:
    any of them
}