rule TTP_XOR_WriteProcessMemory_a83d {
  strings:
    $key_a83d = { ff 4f [2] cd 6d [2] cb 58 [2] e5 58 [2] da 44 }

  condition:
    any of them
}