rule TTP_XOR_WriteProcessMemory_ae4b {
  strings:
    $key_ae4b = { f9 39 [2] cb 1b [2] cd 2e [2] e3 2e [2] dc 32 }

  condition:
    any of them
}