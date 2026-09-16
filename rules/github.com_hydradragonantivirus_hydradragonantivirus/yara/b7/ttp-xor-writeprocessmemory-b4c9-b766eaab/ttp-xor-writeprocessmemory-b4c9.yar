rule TTP_XOR_WriteProcessMemory_b4c9 {
  strings:
    $key_b4c9 = { e3 bb [2] d1 99 [2] d7 ac [2] f9 ac [2] c6 b0 }

  condition:
    any of them
}