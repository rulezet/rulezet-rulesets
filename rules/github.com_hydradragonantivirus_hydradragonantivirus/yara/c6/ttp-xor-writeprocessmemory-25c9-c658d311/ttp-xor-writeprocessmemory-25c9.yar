rule TTP_XOR_WriteProcessMemory_25c9 {
  strings:
    $key_25c9 = { 72 bb [2] 40 99 [2] 46 ac [2] 68 ac [2] 57 b0 }

  condition:
    any of them
}