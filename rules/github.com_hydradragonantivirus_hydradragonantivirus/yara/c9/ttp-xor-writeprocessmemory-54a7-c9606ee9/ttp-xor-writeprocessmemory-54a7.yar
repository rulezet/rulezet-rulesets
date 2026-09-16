rule TTP_XOR_WriteProcessMemory_54a7 {
  strings:
    $key_54a7 = { 03 d5 [2] 31 f7 [2] 37 c2 [2] 19 c2 [2] 26 de }

  condition:
    any of them
}