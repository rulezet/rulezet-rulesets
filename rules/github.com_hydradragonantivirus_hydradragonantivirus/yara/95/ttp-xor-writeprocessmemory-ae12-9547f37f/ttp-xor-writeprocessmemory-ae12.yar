rule TTP_XOR_WriteProcessMemory_ae12 {
  strings:
    $key_ae12 = { f9 60 [2] cb 42 [2] cd 77 [2] e3 77 [2] dc 6b }

  condition:
    any of them
}