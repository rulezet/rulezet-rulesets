rule TTP_XOR_WriteProcessMemory_c281 {
  strings:
    $key_c281 = { 95 f3 [2] a7 d1 [2] a1 e4 [2] 8f e4 [2] b0 f8 }

  condition:
    any of them
}