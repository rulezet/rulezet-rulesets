rule TTP_XOR_WriteProcessMemory_a861 {
  strings:
    $key_a861 = { ff 13 [2] cd 31 [2] cb 04 [2] e5 04 [2] da 18 }

  condition:
    any of them
}