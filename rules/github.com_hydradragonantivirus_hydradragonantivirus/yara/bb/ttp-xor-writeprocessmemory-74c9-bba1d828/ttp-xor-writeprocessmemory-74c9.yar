rule TTP_XOR_WriteProcessMemory_74c9 {
  strings:
    $key_74c9 = { 23 bb [2] 11 99 [2] 17 ac [2] 39 ac [2] 06 b0 }

  condition:
    any of them
}