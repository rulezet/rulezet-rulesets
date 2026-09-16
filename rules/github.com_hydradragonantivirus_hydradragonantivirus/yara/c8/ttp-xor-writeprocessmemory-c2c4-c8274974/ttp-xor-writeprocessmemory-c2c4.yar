rule TTP_XOR_WriteProcessMemory_c2c4 {
  strings:
    $key_c2c4 = { 95 b6 [2] a7 94 [2] a1 a1 [2] 8f a1 [2] b0 bd }

  condition:
    any of them
}