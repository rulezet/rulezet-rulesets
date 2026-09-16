rule TTP_XOR_WriteProcessMemory_6313 {
  strings:
    $key_6313 = { 34 61 [2] 06 43 [2] 00 76 [2] 2e 76 [2] 11 6a }

  condition:
    any of them
}