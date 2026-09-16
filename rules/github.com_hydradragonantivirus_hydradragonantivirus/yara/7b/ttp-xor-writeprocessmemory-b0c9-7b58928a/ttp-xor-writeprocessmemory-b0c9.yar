rule TTP_XOR_WriteProcessMemory_b0c9 {
  strings:
    $key_b0c9 = { e7 bb [2] d5 99 [2] d3 ac [2] fd ac [2] c2 b0 }

  condition:
    any of them
}