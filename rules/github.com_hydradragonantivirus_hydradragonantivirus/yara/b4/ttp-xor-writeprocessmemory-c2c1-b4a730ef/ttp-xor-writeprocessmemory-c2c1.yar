rule TTP_XOR_WriteProcessMemory_c2c1 {
  strings:
    $key_c2c1 = { 95 b3 [2] a7 91 [2] a1 a4 [2] 8f a4 [2] b0 b8 }

  condition:
    any of them
}