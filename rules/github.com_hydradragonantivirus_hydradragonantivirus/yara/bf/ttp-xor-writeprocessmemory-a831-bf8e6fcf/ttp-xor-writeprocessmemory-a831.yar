rule TTP_XOR_WriteProcessMemory_a831 {
  strings:
    $key_a831 = { ff 43 [2] cd 61 [2] cb 54 [2] e5 54 [2] da 48 }

  condition:
    any of them
}