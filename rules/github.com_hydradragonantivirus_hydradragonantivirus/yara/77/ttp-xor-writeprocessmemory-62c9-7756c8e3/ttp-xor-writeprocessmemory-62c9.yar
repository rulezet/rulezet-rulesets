rule TTP_XOR_WriteProcessMemory_62c9 {
  strings:
    $key_62c9 = { 35 bb [2] 07 99 [2] 01 ac [2] 2f ac [2] 10 b0 }

  condition:
    any of them
}