rule TTP_XOR_WriteProcessMemory_eec9 {
  strings:
    $key_eec9 = { b9 bb [2] 8b 99 [2] 8d ac [2] a3 ac [2] 9c b0 }

  condition:
    any of them
}