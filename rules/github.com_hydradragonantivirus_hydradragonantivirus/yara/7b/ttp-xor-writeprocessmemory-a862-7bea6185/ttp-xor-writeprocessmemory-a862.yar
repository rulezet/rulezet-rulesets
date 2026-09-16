rule TTP_XOR_WriteProcessMemory_a862 {
  strings:
    $key_a862 = { ff 10 [2] cd 32 [2] cb 07 [2] e5 07 [2] da 1b }

  condition:
    any of them
}