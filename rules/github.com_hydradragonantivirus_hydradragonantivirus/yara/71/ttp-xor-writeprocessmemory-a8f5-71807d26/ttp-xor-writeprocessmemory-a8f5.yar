rule TTP_XOR_WriteProcessMemory_a8f5 {
  strings:
    $key_a8f5 = { ff 87 [2] cd a5 [2] cb 90 [2] e5 90 [2] da 8c }

  condition:
    any of them
}