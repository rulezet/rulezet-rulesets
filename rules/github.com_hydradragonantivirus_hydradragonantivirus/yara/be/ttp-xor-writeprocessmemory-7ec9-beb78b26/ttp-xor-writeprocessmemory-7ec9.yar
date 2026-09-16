rule TTP_XOR_WriteProcessMemory_7ec9 {
  strings:
    $key_7ec9 = { 29 bb [2] 1b 99 [2] 1d ac [2] 33 ac [2] 0c b0 }

  condition:
    any of them
}