rule TTP_XOR_WriteProcessMemory_5743 {
  strings:
    $key_5743 = { 00 31 [2] 32 13 [2] 34 26 [2] 1a 26 [2] 25 3a }

  condition:
    any of them
}