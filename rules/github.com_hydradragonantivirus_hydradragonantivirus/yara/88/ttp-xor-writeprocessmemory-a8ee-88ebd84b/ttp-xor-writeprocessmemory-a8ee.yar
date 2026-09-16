rule TTP_XOR_WriteProcessMemory_a8ee {
  strings:
    $key_a8ee = { ff 9c [2] cd be [2] cb 8b [2] e5 8b [2] da 97 }

  condition:
    any of them
}