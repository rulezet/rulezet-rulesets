rule TTP_XOR_WriteProcessMemory_aec9 {
  strings:
    $key_aec9 = { f9 bb [2] cb 99 [2] cd ac [2] e3 ac [2] dc b0 }

  condition:
    any of them
}