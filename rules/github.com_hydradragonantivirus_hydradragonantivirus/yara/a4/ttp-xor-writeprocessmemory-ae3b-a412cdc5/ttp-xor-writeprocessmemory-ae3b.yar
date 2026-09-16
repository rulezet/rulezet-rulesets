rule TTP_XOR_WriteProcessMemory_ae3b {
  strings:
    $key_ae3b = { f9 49 [2] cb 6b [2] cd 5e [2] e3 5e [2] dc 42 }

  condition:
    any of them
}