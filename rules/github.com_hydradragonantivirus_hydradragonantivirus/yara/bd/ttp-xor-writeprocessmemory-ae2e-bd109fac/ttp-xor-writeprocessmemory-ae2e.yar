rule TTP_XOR_WriteProcessMemory_ae2e {
  strings:
    $key_ae2e = { f9 5c [2] cb 7e [2] cd 4b [2] e3 4b [2] dc 57 }

  condition:
    any of them
}