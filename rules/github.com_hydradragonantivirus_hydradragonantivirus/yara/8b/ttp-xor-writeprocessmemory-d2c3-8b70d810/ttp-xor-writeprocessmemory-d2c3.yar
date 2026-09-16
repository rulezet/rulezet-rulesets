rule TTP_XOR_WriteProcessMemory_d2c3 {
  strings:
    $key_d2c3 = { 85 b1 [2] b7 93 [2] b1 a6 [2] 9f a6 [2] a0 ba }

  condition:
    any of them
}