rule TTP_XOR_WriteProcessMemory_d2c9 {
  strings:
    $key_d2c9 = { 85 bb [2] b7 99 [2] b1 ac [2] 9f ac [2] a0 b0 }

  condition:
    any of them
}