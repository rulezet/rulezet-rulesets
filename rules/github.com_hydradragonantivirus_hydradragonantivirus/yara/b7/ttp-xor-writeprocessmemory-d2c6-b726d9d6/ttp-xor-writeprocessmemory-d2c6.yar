rule TTP_XOR_WriteProcessMemory_d2c6 {
  strings:
    $key_d2c6 = { 85 b4 [2] b7 96 [2] b1 a3 [2] 9f a3 [2] a0 bf }

  condition:
    any of them
}