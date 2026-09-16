rule TTP_XOR_WriteProcessMemory_27c9 {
  strings:
    $key_27c9 = { 70 bb [2] 42 99 [2] 44 ac [2] 6a ac [2] 55 b0 }

  condition:
    any of them
}