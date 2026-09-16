rule TTP_XOR_WriteProcessMemory_ae2b {
  strings:
    $key_ae2b = { f9 59 [2] cb 7b [2] cd 4e [2] e3 4e [2] dc 52 }

  condition:
    any of them
}