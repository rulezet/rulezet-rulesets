rule TTP_XOR_WriteProcessMemory_c2a6 {
  strings:
    $key_c2a6 = { 95 d4 [2] a7 f6 [2] a1 c3 [2] 8f c3 [2] b0 df }

  condition:
    any of them
}