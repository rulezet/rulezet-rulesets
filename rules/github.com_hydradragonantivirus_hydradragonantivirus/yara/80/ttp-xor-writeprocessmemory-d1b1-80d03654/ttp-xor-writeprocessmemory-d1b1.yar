rule TTP_XOR_WriteProcessMemory_d1b1 {
  strings:
    $key_d1b1 = { 86 c3 [2] b4 e1 [2] b2 d4 [2] 9c d4 [2] a3 c8 }

  condition:
    any of them
}