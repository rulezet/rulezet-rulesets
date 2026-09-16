rule TTP_XOR_WriteProcessMemory_d2a0 {
  strings:
    $key_d2a0 = { 85 d2 [2] b7 f0 [2] b1 c5 [2] 9f c5 [2] a0 d9 }

  condition:
    any of them
}