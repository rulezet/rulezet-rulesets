rule TTP_XOR_WriteProcessMemory_31c9 {
  strings:
    $key_31c9 = { 66 bb [2] 54 99 [2] 52 ac [2] 7c ac [2] 43 b0 }

  condition:
    any of them
}