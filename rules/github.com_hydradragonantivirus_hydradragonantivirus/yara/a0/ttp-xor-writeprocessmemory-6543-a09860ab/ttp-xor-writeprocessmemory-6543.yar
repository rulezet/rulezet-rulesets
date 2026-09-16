rule TTP_XOR_WriteProcessMemory_6543 {
  strings:
    $key_6543 = { 32 31 [2] 00 13 [2] 06 26 [2] 28 26 [2] 17 3a }

  condition:
    any of them
}