rule TTP_XOR_WriteProcessMemory_77c9 {
  strings:
    $key_77c9 = { 20 bb [2] 12 99 [2] 14 ac [2] 3a ac [2] 05 b0 }

  condition:
    any of them
}