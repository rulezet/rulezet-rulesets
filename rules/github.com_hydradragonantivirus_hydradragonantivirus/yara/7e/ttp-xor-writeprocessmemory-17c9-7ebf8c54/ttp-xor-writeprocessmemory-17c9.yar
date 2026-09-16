rule TTP_XOR_WriteProcessMemory_17c9 {
  strings:
    $key_17c9 = { 40 bb [2] 72 99 [2] 74 ac [2] 5a ac [2] 65 b0 }

  condition:
    any of them
}