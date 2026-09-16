rule TTP_XOR_WriteProcessMemory_c1b0 {
  strings:
    $key_c1b0 = { 96 c2 [2] a4 e0 [2] a2 d5 [2] 8c d5 [2] b3 c9 }

  condition:
    any of them
}