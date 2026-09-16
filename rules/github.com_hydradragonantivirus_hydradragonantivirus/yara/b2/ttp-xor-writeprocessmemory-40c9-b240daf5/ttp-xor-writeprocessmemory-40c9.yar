rule TTP_XOR_WriteProcessMemory_40c9 {
  strings:
    $key_40c9 = { 17 bb [2] 25 99 [2] 23 ac [2] 0d ac [2] 32 b0 }

  condition:
    any of them
}