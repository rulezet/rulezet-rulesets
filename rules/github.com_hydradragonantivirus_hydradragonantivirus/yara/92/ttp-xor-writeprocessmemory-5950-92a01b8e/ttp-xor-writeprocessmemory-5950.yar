rule TTP_XOR_WriteProcessMemory_5950 {
  strings:
    $key_5950 = { 0e 22 [2] 3c 00 [2] 3a 35 [2] 14 35 [2] 2b 29 }

  condition:
    any of them
}