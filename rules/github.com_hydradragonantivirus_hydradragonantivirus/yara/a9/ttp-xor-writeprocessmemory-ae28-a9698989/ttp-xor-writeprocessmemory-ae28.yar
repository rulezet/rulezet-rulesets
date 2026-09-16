rule TTP_XOR_WriteProcessMemory_ae28 {
  strings:
    $key_ae28 = { f9 5a [2] cb 78 [2] cd 4d [2] e3 4d [2] dc 51 }

  condition:
    any of them
}