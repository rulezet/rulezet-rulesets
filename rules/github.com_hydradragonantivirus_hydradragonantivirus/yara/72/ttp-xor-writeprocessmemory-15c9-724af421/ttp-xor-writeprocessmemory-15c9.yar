rule TTP_XOR_WriteProcessMemory_15c9 {
  strings:
    $key_15c9 = { 42 bb [2] 70 99 [2] 76 ac [2] 58 ac [2] 67 b0 }

  condition:
    any of them
}