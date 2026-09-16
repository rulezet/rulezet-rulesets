rule TTP_XOR_WriteProcessMemory_a8e9 {
  strings:
    $key_a8e9 = { ff 9b [2] cd b9 [2] cb 8c [2] e5 8c [2] da 90 }

  condition:
    any of them
}