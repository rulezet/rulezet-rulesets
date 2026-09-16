rule TTP_XOR_WriteProcessMemory_b2c9 {
  strings:
    $key_b2c9 = { e5 bb [2] d7 99 [2] d1 ac [2] ff ac [2] c0 b0 }

  condition:
    any of them
}