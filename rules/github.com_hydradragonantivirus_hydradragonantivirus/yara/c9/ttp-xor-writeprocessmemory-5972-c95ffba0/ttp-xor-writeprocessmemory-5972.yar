rule TTP_XOR_WriteProcessMemory_5972 {
  strings:
    $key_5972 = { 0e 00 [2] 3c 22 [2] 3a 17 [2] 14 17 [2] 2b 0b }

  condition:
    any of them
}