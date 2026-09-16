rule TTP_XOR_WriteProcessMemory_82c9 {
  strings:
    $key_82c9 = { d5 bb [2] e7 99 [2] e1 ac [2] cf ac [2] f0 b0 }

  condition:
    any of them
}