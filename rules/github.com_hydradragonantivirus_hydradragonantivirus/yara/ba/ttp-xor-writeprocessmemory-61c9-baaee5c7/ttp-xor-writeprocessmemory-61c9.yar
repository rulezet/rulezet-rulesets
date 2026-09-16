rule TTP_XOR_WriteProcessMemory_61c9 {
  strings:
    $key_61c9 = { 36 bb [2] 04 99 [2] 02 ac [2] 2c ac [2] 13 b0 }

  condition:
    any of them
}