rule TTP_XOR_WriteProcessMemory_a8d2 {
  strings:
    $key_a8d2 = { ff a0 [2] cd 82 [2] cb b7 [2] e5 b7 [2] da ab }

  condition:
    any of them
}