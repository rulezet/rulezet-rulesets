rule TTP_XOR_WriteProcessMemory_6359 {
  strings:
    $key_6359 = { 34 2b [2] 06 09 [2] 00 3c [2] 2e 3c [2] 11 20 }

  condition:
    any of them
}