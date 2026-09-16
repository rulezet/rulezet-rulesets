rule TTP_XOR_WriteProcessMemory_a2c9 {
  strings:
    $key_a2c9 = { f5 bb [2] c7 99 [2] c1 ac [2] ef ac [2] d0 b0 }

  condition:
    any of them
}