rule TTP_XOR_WriteProcessMemory_ae13 {
  strings:
    $key_ae13 = { f9 61 [2] cb 43 [2] cd 76 [2] e3 76 [2] dc 6a }

  condition:
    any of them
}