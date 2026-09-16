rule TTP_XOR_WriteProcessMemory_d7c9 {
  strings:
    $key_d7c9 = { 80 bb [2] b2 99 [2] b4 ac [2] 9a ac [2] a5 b0 }

  condition:
    any of them
}