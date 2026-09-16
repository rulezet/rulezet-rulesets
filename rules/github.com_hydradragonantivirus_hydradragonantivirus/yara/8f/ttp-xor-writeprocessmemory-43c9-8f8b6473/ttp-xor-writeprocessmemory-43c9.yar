rule TTP_XOR_WriteProcessMemory_43c9 {
  strings:
    $key_43c9 = { 14 bb [2] 26 99 [2] 20 ac [2] 0e ac [2] 31 b0 }

  condition:
    any of them
}