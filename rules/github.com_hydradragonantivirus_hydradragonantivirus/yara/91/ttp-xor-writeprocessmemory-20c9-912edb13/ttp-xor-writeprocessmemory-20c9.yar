rule TTP_XOR_WriteProcessMemory_20c9 {
  strings:
    $key_20c9 = { 77 bb [2] 45 99 [2] 43 ac [2] 6d ac [2] 52 b0 }

  condition:
    any of them
}