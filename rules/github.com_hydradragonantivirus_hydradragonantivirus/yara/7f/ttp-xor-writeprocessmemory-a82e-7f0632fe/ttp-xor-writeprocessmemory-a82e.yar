rule TTP_XOR_WriteProcessMemory_a82e {
  strings:
    $key_a82e = { ff 5c [2] cd 7e [2] cb 4b [2] e5 4b [2] da 57 }

  condition:
    any of them
}