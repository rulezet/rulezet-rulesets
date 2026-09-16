rule TTP_XOR_WriteProcessMemory_b6c9 {
  strings:
    $key_b6c9 = { e1 bb [2] d3 99 [2] d5 ac [2] fb ac [2] c4 b0 }

  condition:
    any of them
}