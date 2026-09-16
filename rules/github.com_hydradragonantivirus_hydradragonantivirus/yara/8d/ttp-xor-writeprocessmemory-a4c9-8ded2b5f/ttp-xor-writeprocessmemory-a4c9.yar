rule TTP_XOR_WriteProcessMemory_a4c9 {
  strings:
    $key_a4c9 = { f3 bb [2] c1 99 [2] c7 ac [2] e9 ac [2] d6 b0 }

  condition:
    any of them
}