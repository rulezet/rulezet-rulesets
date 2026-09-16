rule TTP_XOR_WriteProcessMemory_5752 {
  strings:
    $key_5752 = { 00 20 [2] 32 02 [2] 34 37 [2] 1a 37 [2] 25 2b }

  condition:
    any of them
}