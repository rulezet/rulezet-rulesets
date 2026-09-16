rule TTP_XOR_WriteProcessMemory_13c9 {
  strings:
    $key_13c9 = { 44 bb [2] 76 99 [2] 70 ac [2] 5e ac [2] 61 b0 }

  condition:
    any of them
}