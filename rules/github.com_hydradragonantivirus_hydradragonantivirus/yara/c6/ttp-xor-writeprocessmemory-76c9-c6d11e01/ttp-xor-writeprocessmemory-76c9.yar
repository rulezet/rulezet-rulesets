rule TTP_XOR_WriteProcessMemory_76c9 {
  strings:
    $key_76c9 = { 21 bb [2] 13 99 [2] 15 ac [2] 3b ac [2] 04 b0 }

  condition:
    any of them
}