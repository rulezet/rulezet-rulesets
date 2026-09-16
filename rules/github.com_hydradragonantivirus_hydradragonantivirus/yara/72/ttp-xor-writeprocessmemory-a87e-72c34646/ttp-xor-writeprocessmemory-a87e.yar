rule TTP_XOR_WriteProcessMemory_a87e {
  strings:
    $key_a87e = { ff 0c [2] cd 2e [2] cb 1b [2] e5 1b [2] da 07 }

  condition:
    any of them
}