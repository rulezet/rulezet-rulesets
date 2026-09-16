rule TTP_XOR_WriteProcessMemory_d1c9 {
  strings:
    $key_d1c9 = { 86 bb [2] b4 99 [2] b2 ac [2] 9c ac [2] a3 b0 }

  condition:
    any of them
}