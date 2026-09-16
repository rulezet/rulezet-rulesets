rule TTP_XOR_WriteProcessMemory_c0c9 {
  strings:
    $key_c0c9 = { 97 bb [2] a5 99 [2] a3 ac [2] 8d ac [2] b2 b0 }

  condition:
    any of them
}