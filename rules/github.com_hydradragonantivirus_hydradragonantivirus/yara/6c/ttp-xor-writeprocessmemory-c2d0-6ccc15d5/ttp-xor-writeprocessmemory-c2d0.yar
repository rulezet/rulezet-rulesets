rule TTP_XOR_WriteProcessMemory_c2d0 {
  strings:
    $key_c2d0 = { 95 a2 [2] a7 80 [2] a1 b5 [2] 8f b5 [2] b0 a9 }

  condition:
    any of them
}