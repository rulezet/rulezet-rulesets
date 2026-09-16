rule TTP_XOR_WriteProcessMemory_ae48 {
  strings:
    $key_ae48 = { f9 3a [2] cb 18 [2] cd 2d [2] e3 2d [2] dc 31 }

  condition:
    any of them
}