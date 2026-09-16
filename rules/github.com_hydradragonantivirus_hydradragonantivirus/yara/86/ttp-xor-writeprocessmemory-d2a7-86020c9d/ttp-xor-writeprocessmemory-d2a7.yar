rule TTP_XOR_WriteProcessMemory_d2a7 {
  strings:
    $key_d2a7 = { 85 d5 [2] b7 f7 [2] b1 c2 [2] 9f c2 [2] a0 de }

  condition:
    any of them
}