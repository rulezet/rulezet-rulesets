rule TTP_XOR_WriteProcessMemory_d2b1 {
  strings:
    $key_d2b1 = { 85 c3 [2] b7 e1 [2] b1 d4 [2] 9f d4 [2] a0 c8 }

  condition:
    any of them
}