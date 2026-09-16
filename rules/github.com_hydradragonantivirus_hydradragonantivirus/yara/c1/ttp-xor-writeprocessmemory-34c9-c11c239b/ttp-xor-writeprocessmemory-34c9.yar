rule TTP_XOR_WriteProcessMemory_34c9 {
  strings:
    $key_34c9 = { 63 bb [2] 51 99 [2] 57 ac [2] 79 ac [2] 46 b0 }

  condition:
    any of them
}