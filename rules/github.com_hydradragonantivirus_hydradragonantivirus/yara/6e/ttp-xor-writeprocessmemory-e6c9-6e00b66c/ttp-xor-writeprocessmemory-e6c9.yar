rule TTP_XOR_WriteProcessMemory_e6c9 {
  strings:
    $key_e6c9 = { b1 bb [2] 83 99 [2] 85 ac [2] ab ac [2] 94 b0 }

  condition:
    any of them
}