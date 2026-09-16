rule TTP_XOR_WriteProcessMemory_1d50 {
  strings:
    $key_1d50 = { 4a 22 [2] 78 00 [2] 7e 35 [2] 50 35 [2] 6f 29 }

  condition:
    any of them
}