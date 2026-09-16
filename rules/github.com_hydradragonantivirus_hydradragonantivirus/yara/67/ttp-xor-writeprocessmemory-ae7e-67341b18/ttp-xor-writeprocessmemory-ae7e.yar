rule TTP_XOR_WriteProcessMemory_ae7e {
  strings:
    $key_ae7e = { f9 0c [2] cb 2e [2] cd 1b [2] e3 1b [2] dc 07 }

  condition:
    any of them
}