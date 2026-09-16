rule TTP_XOR_WriteProcessMemory_ae40 {
  strings:
    $key_ae40 = { f9 32 [2] cb 10 [2] cd 25 [2] e3 25 [2] dc 39 }

  condition:
    any of them
}