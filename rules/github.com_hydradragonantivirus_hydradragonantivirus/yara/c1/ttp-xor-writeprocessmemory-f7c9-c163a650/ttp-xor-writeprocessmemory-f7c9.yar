rule TTP_XOR_WriteProcessMemory_f7c9 {
  strings:
    $key_f7c9 = { a0 bb [2] 92 99 [2] 94 ac [2] ba ac [2] 85 b0 }

  condition:
    any of them
}