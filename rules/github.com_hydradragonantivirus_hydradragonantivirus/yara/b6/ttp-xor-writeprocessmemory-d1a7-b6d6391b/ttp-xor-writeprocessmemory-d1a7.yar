rule TTP_XOR_WriteProcessMemory_d1a7 {
  strings:
    $key_d1a7 = { 86 d5 [2] b4 f7 [2] b2 c2 [2] 9c c2 [2] a3 de }

  condition:
    any of them
}