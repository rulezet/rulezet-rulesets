rule TTP_XOR_WriteProcessMemory_c2a3 {
  strings:
    $key_c2a3 = { 95 d1 [2] a7 f3 [2] a1 c6 [2] 8f c6 [2] b0 da }

  condition:
    any of them
}