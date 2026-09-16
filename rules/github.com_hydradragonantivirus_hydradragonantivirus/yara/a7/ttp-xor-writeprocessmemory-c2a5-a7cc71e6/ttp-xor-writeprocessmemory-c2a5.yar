rule TTP_XOR_WriteProcessMemory_c2a5 {
  strings:
    $key_c2a5 = { 95 d7 [2] a7 f5 [2] a1 c0 [2] 8f c0 [2] b0 dc }

  condition:
    any of them
}