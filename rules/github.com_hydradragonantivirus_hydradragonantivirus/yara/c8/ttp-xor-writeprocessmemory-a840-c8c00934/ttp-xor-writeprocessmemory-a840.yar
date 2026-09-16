rule TTP_XOR_WriteProcessMemory_a840 {
  strings:
    $key_a840 = { ff 32 [2] cd 10 [2] cb 25 [2] e5 25 [2] da 39 }

  condition:
    any of them
}