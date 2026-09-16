rule TTP_XOR_WriteProcessMemory_93c9 {
  strings:
    $key_93c9 = { c4 bb [2] f6 99 [2] f0 ac [2] de ac [2] e1 b0 }

  condition:
    any of them
}