rule TTP_XOR_WriteProcessMemory_45a7 {
  strings:
    $key_45a7 = { 12 d5 [2] 20 f7 [2] 26 c2 [2] 08 c2 [2] 37 de }

  condition:
    any of them
}