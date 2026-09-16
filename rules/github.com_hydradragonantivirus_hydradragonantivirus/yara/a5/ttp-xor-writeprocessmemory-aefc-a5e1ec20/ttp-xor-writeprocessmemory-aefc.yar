rule TTP_XOR_WriteProcessMemory_aefc {
  strings:
    $key_aefc = { f9 8e [2] cb ac [2] cd 99 [2] e3 99 [2] dc 85 }

  condition:
    any of them
}