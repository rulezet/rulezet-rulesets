rule TTP_XOR_WriteProcessMemory_d2a3 {
  strings:
    $key_d2a3 = { 85 d1 [2] b7 f3 [2] b1 c6 [2] 9f c6 [2] a0 da }

  condition:
    any of them
}