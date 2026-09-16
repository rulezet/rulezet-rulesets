rule TTP_XOR_WriteProcessMemory_6350 {
  strings:
    $key_6350 = { 34 22 [2] 06 00 [2] 00 35 [2] 2e 35 [2] 11 29 }

  condition:
    any of them
}