rule TTP_XOR_WriteProcessMemory_a879 {
  strings:
    $key_a879 = { ff 0b [2] cd 29 [2] cb 1c [2] e5 1c [2] da 00 }

  condition:
    any of them
}