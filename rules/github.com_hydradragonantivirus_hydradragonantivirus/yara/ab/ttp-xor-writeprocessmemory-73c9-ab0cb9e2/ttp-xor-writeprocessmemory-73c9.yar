rule TTP_XOR_WriteProcessMemory_73c9 {
  strings:
    $key_73c9 = { 24 bb [2] 16 99 [2] 10 ac [2] 3e ac [2] 01 b0 }

  condition:
    any of them
}