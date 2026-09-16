rule TTP_XOR_WriteProcessMemory_a8c9 {
  strings:
    $key_a8c9 = { ff bb [2] cd 99 [2] cb ac [2] e5 ac [2] da b0 }

  condition:
    any of them
}