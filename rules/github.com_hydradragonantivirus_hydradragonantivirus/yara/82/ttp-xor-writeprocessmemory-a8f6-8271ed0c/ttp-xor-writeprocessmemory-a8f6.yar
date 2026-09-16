rule TTP_XOR_WriteProcessMemory_a8f6 {
  strings:
    $key_a8f6 = { ff 84 [2] cd a6 [2] cb 93 [2] e5 93 [2] da 8f }

  condition:
    any of them
}