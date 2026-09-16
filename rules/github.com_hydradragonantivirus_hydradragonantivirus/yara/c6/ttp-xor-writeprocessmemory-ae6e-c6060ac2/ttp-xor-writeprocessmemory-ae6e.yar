rule TTP_XOR_WriteProcessMemory_ae6e {
  strings:
    $key_ae6e = { f9 1c [2] cb 3e [2] cd 0b [2] e3 0b [2] dc 17 }

  condition:
    any of them
}