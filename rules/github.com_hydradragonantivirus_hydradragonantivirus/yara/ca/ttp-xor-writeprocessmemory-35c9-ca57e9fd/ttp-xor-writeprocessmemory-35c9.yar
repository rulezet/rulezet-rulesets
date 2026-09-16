rule TTP_XOR_WriteProcessMemory_35c9 {
  strings:
    $key_35c9 = { 62 bb [2] 50 99 [2] 56 ac [2] 78 ac [2] 47 b0 }

  condition:
    any of them
}