rule TTP_XOR_WriteProcessMemory_5777 {
  strings:
    $key_5777 = { 00 05 [2] 32 27 [2] 34 12 [2] 1a 12 [2] 25 0e }

  condition:
    any of them
}