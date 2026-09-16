rule TTP_XOR_WriteProcessMemory_2ec9 {
  strings:
    $key_2ec9 = { 79 bb [2] 4b 99 [2] 4d ac [2] 63 ac [2] 5c b0 }

  condition:
    any of them
}