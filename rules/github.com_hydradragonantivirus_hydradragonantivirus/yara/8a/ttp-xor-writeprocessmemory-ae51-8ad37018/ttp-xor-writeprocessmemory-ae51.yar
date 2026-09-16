rule TTP_XOR_WriteProcessMemory_ae51 {
  strings:
    $key_ae51 = { f9 23 [2] cb 01 [2] cd 34 [2] e3 34 [2] dc 28 }

  condition:
    any of them
}