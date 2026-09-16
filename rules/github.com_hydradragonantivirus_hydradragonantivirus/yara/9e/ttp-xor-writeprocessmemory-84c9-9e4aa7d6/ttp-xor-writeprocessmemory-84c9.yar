rule TTP_XOR_WriteProcessMemory_84c9 {
  strings:
    $key_84c9 = { d3 bb [2] e1 99 [2] e7 ac [2] c9 ac [2] f6 b0 }

  condition:
    any of them
}