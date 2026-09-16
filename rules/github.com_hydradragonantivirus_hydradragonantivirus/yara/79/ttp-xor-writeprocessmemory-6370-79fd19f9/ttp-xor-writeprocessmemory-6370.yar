rule TTP_XOR_WriteProcessMemory_6370 {
  strings:
    $key_6370 = { 34 02 [2] 06 20 [2] 00 15 [2] 2e 15 [2] 11 09 }

  condition:
    any of them
}