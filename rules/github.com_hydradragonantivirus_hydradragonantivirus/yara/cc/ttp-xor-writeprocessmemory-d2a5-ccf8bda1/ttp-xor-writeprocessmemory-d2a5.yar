rule TTP_XOR_WriteProcessMemory_d2a5 {
  strings:
    $key_d2a5 = { 85 d7 [2] b7 f5 [2] b1 c0 [2] 9f c0 [2] a0 dc }

  condition:
    any of them
}