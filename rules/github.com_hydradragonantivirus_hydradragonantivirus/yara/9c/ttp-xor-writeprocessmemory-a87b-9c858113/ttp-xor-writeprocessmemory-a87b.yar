rule TTP_XOR_WriteProcessMemory_a87b {
  strings:
    $key_a87b = { ff 09 [2] cd 2b [2] cb 1e [2] e5 1e [2] da 02 }

  condition:
    any of them
}