rule TTP_XOR_WriteProcessMemory_a8b7 {
  strings:
    $key_a8b7 = { ff c5 [2] cd e7 [2] cb d2 [2] e5 d2 [2] da ce }

  condition:
    any of them
}