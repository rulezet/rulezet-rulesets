rule TTP_XOR_WriteProcessMemory_05c9 {
  strings:
    $key_05c9 = { 52 bb [2] 60 99 [2] 66 ac [2] 48 ac [2] 77 b0 }

  condition:
    any of them
}