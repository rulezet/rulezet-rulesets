rule TTP_XOR_WriteProcessMemory_5767 {
  strings:
    $key_5767 = { 00 15 [2] 32 37 [2] 34 02 [2] 1a 02 [2] 25 1e }

  condition:
    any of them
}