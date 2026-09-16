rule TTP_XOR_WriteProcessMemory_73a7 {
  strings:
    $key_73a7 = { 24 d5 [2] 16 f7 [2] 10 c2 [2] 3e c2 [2] 01 de }

  condition:
    any of them
}