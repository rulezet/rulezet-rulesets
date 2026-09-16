rule TTP_XOR_WriteProcessMemory_ae20 {
  strings:
    $key_ae20 = { f9 52 [2] cb 70 [2] cd 45 [2] e3 45 [2] dc 59 }

  condition:
    any of them
}