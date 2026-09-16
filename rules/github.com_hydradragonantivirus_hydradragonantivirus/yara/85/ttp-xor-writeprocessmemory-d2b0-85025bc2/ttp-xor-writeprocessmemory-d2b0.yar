rule TTP_XOR_WriteProcessMemory_d2b0 {
  strings:
    $key_d2b0 = { 85 c2 [2] b7 e0 [2] b1 d5 [2] 9f d5 [2] a0 c9 }

  condition:
    any of them
}