rule TTP_XOR_WriteProcessMemory_ae78 {
  strings:
    $key_ae78 = { f9 0a [2] cb 28 [2] cd 1d [2] e3 1d [2] dc 01 }

  condition:
    any of them
}