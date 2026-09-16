rule TTP_XOR_WriteProcessMemory_96c9 {
  strings:
    $key_96c9 = { c1 bb [2] f3 99 [2] f5 ac [2] db ac [2] e4 b0 }

  condition:
    any of them
}