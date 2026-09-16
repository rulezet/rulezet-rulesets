rule TTP_XOR_WriteProcessMemory_c2d4 {
  strings:
    $key_c2d4 = { 95 a6 [2] a7 84 [2] a1 b1 [2] 8f b1 [2] b0 ad }

  condition:
    any of them
}