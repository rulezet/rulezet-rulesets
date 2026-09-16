rule TTP_XOR_WriteProcessMemory_a868 {
  strings:
    $key_a868 = { ff 1a [2] cd 38 [2] cb 0d [2] e5 0d [2] da 11 }

  condition:
    any of them
}