rule TTP_XOR_WriteProcessMemory_5ec9 {
  strings:
    $key_5ec9 = { 09 bb [2] 3b 99 [2] 3d ac [2] 13 ac [2] 2c b0 }

  condition:
    any of them
}