rule TTP_XOR_WriteProcessMemory_ae0e {
  strings:
    $key_ae0e = { f9 7c [2] cb 5e [2] cd 6b [2] e3 6b [2] dc 77 }

  condition:
    any of them
}