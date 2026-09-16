rule TTP_XOR_WriteProcessMemory_80c9 {
  strings:
    $key_80c9 = { d7 bb [2] e5 99 [2] e3 ac [2] cd ac [2] f2 b0 }

  condition:
    any of them
}