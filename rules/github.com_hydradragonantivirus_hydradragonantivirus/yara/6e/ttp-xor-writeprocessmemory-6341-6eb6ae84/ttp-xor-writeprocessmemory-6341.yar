rule TTP_XOR_WriteProcessMemory_6341 {
  strings:
    $key_6341 = { 34 33 [2] 06 11 [2] 00 24 [2] 2e 24 [2] 11 38 }

  condition:
    any of them
}