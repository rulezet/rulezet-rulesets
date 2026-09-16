rule TTP_XOR_WriteProcessMemory_1ec9 {
  strings:
    $key_1ec9 = { 49 bb [2] 7b 99 [2] 7d ac [2] 53 ac [2] 6c b0 }

  condition:
    any of them
}