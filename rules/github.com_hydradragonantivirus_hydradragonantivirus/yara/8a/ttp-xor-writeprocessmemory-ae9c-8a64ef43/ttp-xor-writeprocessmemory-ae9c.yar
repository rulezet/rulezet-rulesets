rule TTP_XOR_WriteProcessMemory_ae9c {
  strings:
    $key_ae9c = { f9 ee [2] cb cc [2] cd f9 [2] e3 f9 [2] dc e5 }

  condition:
    any of them
}