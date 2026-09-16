rule TTP_XOR_WriteProcessMemory_47a7 {
  strings:
    $key_47a7 = { 10 d5 [2] 22 f7 [2] 24 c2 [2] 0a c2 [2] 35 de }

  condition:
    any of them
}