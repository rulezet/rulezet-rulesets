rule TTP_XOR_WriteProcessMemory_a8f3 {
  strings:
    $key_a8f3 = { ff 81 [2] cd a3 [2] cb 96 [2] e5 96 [2] da 8a }

  condition:
    any of them
}