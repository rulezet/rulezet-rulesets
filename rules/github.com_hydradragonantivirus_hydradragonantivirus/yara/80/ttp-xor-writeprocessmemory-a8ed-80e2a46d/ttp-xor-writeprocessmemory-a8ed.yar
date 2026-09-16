rule TTP_XOR_WriteProcessMemory_a8ed {
  strings:
    $key_a8ed = { ff 9f [2] cd bd [2] cb 88 [2] e5 88 [2] da 94 }

  condition:
    any of them
}