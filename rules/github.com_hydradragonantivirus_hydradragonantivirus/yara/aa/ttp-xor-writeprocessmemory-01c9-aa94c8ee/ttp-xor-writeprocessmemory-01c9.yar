rule TTP_XOR_WriteProcessMemory_01c9 {
  strings:
    $key_01c9 = { 56 bb [2] 64 99 [2] 62 ac [2] 4c ac [2] 73 b0 }

  condition:
    any of them
}