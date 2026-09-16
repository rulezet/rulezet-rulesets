rule TTP_XOR_WriteProcessMemory_25a7 {
  strings:
    $key_25a7 = { 72 d5 [2] 40 f7 [2] 46 c2 [2] 68 c2 [2] 57 de }

  condition:
    any of them
}