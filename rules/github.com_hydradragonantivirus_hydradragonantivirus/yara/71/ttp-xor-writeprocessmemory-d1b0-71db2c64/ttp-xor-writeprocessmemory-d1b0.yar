rule TTP_XOR_WriteProcessMemory_d1b0 {
  strings:
    $key_d1b0 = { 86 c2 [2] b4 e0 [2] b2 d5 [2] 9c d5 [2] a3 c9 }

  condition:
    any of them
}