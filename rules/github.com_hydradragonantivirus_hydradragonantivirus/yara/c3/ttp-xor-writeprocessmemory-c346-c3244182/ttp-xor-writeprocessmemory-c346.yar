rule TTP_XOR_WriteProcessMemory_c346 {
  strings:
    $key_c346 = { 94 34 [2] a6 16 [2] a0 23 [2] 8e 23 [2] b1 3f }

  condition:
    any of them
}