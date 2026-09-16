rule TTP_XOR_WriteProcessMemory_d2d0 {
  strings:
    $key_d2d0 = { 85 a2 [2] b7 80 [2] b1 b5 [2] 9f b5 [2] a0 a9 }

  condition:
    any of them
}