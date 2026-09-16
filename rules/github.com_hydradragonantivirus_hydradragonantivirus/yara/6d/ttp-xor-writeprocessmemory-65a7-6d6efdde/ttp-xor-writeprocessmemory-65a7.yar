rule TTP_XOR_WriteProcessMemory_65a7 {
  strings:
    $key_65a7 = { 32 d5 [2] 00 f7 [2] 06 c2 [2] 28 c2 [2] 17 de }

  condition:
    any of them
}