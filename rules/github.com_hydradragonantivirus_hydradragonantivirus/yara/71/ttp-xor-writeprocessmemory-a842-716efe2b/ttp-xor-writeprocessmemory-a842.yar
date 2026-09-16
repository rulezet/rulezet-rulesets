rule TTP_XOR_WriteProcessMemory_a842 {
  strings:
    $key_a842 = { ff 30 [2] cd 12 [2] cb 27 [2] e5 27 [2] da 3b }

  condition:
    any of them
}