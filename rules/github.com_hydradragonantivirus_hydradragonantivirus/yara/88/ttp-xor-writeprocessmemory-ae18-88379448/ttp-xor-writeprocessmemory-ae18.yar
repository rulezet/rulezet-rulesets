rule TTP_XOR_WriteProcessMemory_ae18 {
  strings:
    $key_ae18 = { f9 6a [2] cb 48 [2] cd 7d [2] e3 7d [2] dc 61 }

  condition:
    any of them
}