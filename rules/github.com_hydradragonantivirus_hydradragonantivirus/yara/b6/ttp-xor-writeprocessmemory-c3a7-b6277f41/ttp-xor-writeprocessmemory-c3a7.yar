rule TTP_XOR_WriteProcessMemory_c3a7 {
  strings:
    $key_c3a7 = { 94 d5 [2] a6 f7 [2] a0 c2 [2] 8e c2 [2] b1 de }

  condition:
    any of them
}