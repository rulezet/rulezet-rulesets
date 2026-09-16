rule TTP_XOR_WriteProcessMemory_66c9 {
  strings:
    $key_66c9 = { 31 bb [2] 03 99 [2] 05 ac [2] 2b ac [2] 14 b0 }

  condition:
    any of them
}