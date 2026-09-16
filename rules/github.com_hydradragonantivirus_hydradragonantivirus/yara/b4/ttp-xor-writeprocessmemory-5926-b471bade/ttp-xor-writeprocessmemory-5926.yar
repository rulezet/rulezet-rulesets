rule TTP_XOR_WriteProcessMemory_5926 {
  strings:
    $key_5926 = { 0e 54 [2] 3c 76 [2] 3a 43 [2] 14 43 [2] 2b 5f }

  condition:
    any of them
}