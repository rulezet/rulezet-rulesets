rule TTP_XOR_WriteProcessMemory_d2c1 {
  strings:
    $key_d2c1 = { 85 b3 [2] b7 91 [2] b1 a4 [2] 9f a4 [2] a0 b8 }

  condition:
    any of them
}