rule TTP_XOR_WriteProcessMemory_ae3e {
  strings:
    $key_ae3e = { f9 4c [2] cb 6e [2] cd 5b [2] e3 5b [2] dc 47 }

  condition:
    any of them
}