rule TTP_XOR_WriteProcessMemory_a8af {
  strings:
    $key_a8af = { ff dd [2] cd ff [2] cb ca [2] e5 ca [2] da d6 }

  condition:
    any of them
}