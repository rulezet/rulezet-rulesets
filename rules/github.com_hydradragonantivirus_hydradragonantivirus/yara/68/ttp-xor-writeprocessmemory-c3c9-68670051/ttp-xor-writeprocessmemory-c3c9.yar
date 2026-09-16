rule TTP_XOR_WriteProcessMemory_c3c9 {
  strings:
    $key_c3c9 = { 94 bb [2] a6 99 [2] a0 ac [2] 8e ac [2] b1 b0 }

  condition:
    any of them
}