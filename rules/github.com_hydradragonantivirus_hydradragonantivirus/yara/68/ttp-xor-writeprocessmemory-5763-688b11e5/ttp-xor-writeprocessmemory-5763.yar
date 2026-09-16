rule TTP_XOR_WriteProcessMemory_5763 {
  strings:
    $key_5763 = { 00 11 [2] 32 33 [2] 34 06 [2] 1a 06 [2] 25 1a }

  condition:
    any of them
}