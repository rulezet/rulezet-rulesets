rule TTP_XOR_WriteProcessMemory_45c9 {
  strings:
    $key_45c9 = { 12 bb [2] 20 99 [2] 26 ac [2] 08 ac [2] 37 b0 }

  condition:
    any of them
}