rule TTP_XOR_WriteProcessMemory_a8e4 {
  strings:
    $key_a8e4 = { ff 96 [2] cd b4 [2] cb 81 [2] e5 81 [2] da 9d }

  condition:
    any of them
}