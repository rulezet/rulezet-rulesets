rule TTP_XOR_WriteProcessMemory_2fc9 {
  strings:
    $key_2fc9 = { 78 bb [2] 4a 99 [2] 4c ac [2] 62 ac [2] 5d b0 }

  condition:
    any of them
}