rule TTP_XOR_WriteProcessMemory_fec9 {
  strings:
    $key_fec9 = { a9 bb [2] 9b 99 [2] 9d ac [2] b3 ac [2] 8c b0 }

  condition:
    any of them
}