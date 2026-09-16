rule TTP_XOR_WriteProcessMemory_a873 {
  strings:
    $key_a873 = { ff 01 [2] cd 23 [2] cb 16 [2] e5 16 [2] da 0a }

  condition:
    any of them
}