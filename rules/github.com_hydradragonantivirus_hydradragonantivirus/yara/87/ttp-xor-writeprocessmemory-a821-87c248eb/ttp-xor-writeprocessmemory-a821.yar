rule TTP_XOR_WriteProcessMemory_a821 {
  strings:
    $key_a821 = { ff 53 [2] cd 71 [2] cb 44 [2] e5 44 [2] da 58 }

  condition:
    any of them
}