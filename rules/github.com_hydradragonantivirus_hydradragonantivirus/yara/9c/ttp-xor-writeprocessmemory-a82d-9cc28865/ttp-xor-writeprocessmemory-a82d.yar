rule TTP_XOR_WriteProcessMemory_a82d {
  strings:
    $key_a82d = { ff 5f [2] cd 7d [2] cb 48 [2] e5 48 [2] da 54 }

  condition:
    any of them
}