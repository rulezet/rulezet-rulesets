rule TTP_XOR_WriteProcessMemory_c1b1 {
  strings:
    $key_c1b1 = { 96 c3 [2] a4 e1 [2] a2 d4 [2] 8c d4 [2] b3 c8 }

  condition:
    any of them
}