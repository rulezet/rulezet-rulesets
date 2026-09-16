rule TTP_XOR_WriteProcessMemory_32a7 {
  strings:
    $key_32a7 = { 65 d5 [2] 57 f7 [2] 51 c2 [2] 7f c2 [2] 40 de }

  condition:
    any of them
}