rule TTP_XOR_WriteProcessMemory_63c9 {
  strings:
    $key_63c9 = { 34 bb [2] 06 99 [2] 00 ac [2] 2e ac [2] 11 b0 }

  condition:
    any of them
}