rule TTP_XOR_WriteProcessMemory_6300 {
  strings:
    $key_6300 = { 34 72 [2] 06 50 [2] 00 65 [2] 2e 65 [2] 11 79 }

  condition:
    any of them
}