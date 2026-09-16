rule TTP_XOR_WriteProcessMemory_50a7 {
  strings:
    $key_50a7 = { 07 d5 [2] 35 f7 [2] 33 c2 [2] 1d c2 [2] 22 de }

  condition:
    any of them
}