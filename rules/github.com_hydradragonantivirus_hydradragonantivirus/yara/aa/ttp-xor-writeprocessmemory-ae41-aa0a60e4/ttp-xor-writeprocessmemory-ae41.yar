rule TTP_XOR_WriteProcessMemory_ae41 {
  strings:
    $key_ae41 = { f9 33 [2] cb 11 [2] cd 24 [2] e3 24 [2] dc 38 }

  condition:
    any of them
}