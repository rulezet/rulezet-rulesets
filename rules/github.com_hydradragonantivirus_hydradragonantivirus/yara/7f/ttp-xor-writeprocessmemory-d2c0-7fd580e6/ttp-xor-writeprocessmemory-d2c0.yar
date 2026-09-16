rule TTP_XOR_WriteProcessMemory_d2c0 {
  strings:
    $key_d2c0 = { 85 b2 [2] b7 90 [2] b1 a5 [2] 9f a5 [2] a0 b9 }

  condition:
    any of them
}