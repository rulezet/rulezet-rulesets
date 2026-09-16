rule TTP_XOR_WriteProcessMemory_41c9 {
  strings:
    $key_41c9 = { 16 bb [2] 24 99 [2] 22 ac [2] 0c ac [2] 33 b0 }

  condition:
    any of them
}