rule TTP_XOR_WriteProcessMemory_c2b0 {
  strings:
    $key_c2b0 = { 95 c2 [2] a7 e0 [2] a1 d5 [2] 8f d5 [2] b0 c9 }

  condition:
    any of them
}