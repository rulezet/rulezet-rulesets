rule TTP_XOR_WriteProcessMemory_ae50 {
  strings:
    $key_ae50 = { f9 22 [2] cb 00 [2] cd 35 [2] e3 35 [2] dc 29 }

  condition:
    any of them
}