rule TTP_XOR_WriteProcessMemory_c4c9 {
  strings:
    $key_c4c9 = { 93 bb [2] a1 99 [2] a7 ac [2] 89 ac [2] b6 b0 }

  condition:
    any of them
}