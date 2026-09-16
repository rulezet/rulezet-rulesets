rule TTP_XOR_WriteProcessMemory_75a7 {
  strings:
    $key_75a7 = { 22 d5 [2] 10 f7 [2] 16 c2 [2] 38 c2 [2] 07 de }

  condition:
    any of them
}