rule TTP_XOR_WriteProcessMemory_d0c9 {
  strings:
    $key_d0c9 = { 87 bb [2] b5 99 [2] b3 ac [2] 9d ac [2] a2 b0 }

  condition:
    any of them
}