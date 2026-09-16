rule TTP_XOR_WriteProcessMemory_35a7 {
  strings:
    $key_35a7 = { 62 d5 [2] 50 f7 [2] 56 c2 [2] 78 c2 [2] 47 de }

  condition:
    any of them
}