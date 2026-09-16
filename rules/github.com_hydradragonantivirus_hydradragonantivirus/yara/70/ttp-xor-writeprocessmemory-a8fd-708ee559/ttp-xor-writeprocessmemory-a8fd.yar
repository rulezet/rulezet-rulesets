rule TTP_XOR_WriteProcessMemory_a8fd {
  strings:
    $key_a8fd = { ff 8f [2] cd ad [2] cb 98 [2] e5 98 [2] da 84 }

  condition:
    any of them
}