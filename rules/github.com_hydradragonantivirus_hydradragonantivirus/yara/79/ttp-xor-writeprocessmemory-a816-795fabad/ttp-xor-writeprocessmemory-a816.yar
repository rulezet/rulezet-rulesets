rule TTP_XOR_WriteProcessMemory_a816 {
  strings:
    $key_a816 = { ff 64 [2] cd 46 [2] cb 73 [2] e5 73 [2] da 6f }

  condition:
    any of them
}