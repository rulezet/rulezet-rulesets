rule TTP_XOR_WriteProcessMemory_a833 {
  strings:
    $key_a833 = { ff 41 [2] cd 63 [2] cb 56 [2] e5 56 [2] da 4a }

  condition:
    any of them
}