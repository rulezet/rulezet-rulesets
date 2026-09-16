rule TTP_XOR_WriteProcessMemory_e0c9 {
  strings:
    $key_e0c9 = { b7 bb [2] 85 99 [2] 83 ac [2] ad ac [2] 92 b0 }

  condition:
    any of them
}