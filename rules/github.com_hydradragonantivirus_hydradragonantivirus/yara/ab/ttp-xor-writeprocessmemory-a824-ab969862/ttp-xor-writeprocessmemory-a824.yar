rule TTP_XOR_WriteProcessMemory_a824 {
  strings:
    $key_a824 = { ff 56 [2] cd 74 [2] cb 41 [2] e5 41 [2] da 5d }

  condition:
    any of them
}