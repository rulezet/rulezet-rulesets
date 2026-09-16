rule TTP_XOR_WriteProcessMemory_6308 {
  strings:
    $key_6308 = { 34 7a [2] 06 58 [2] 00 6d [2] 2e 6d [2] 11 71 }

  condition:
    any of them
}