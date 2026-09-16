rule TTP_XOR_WriteProcessMemory_ae10 {
  strings:
    $key_ae10 = { f9 62 [2] cb 40 [2] cd 75 [2] e3 75 [2] dc 69 }

  condition:
    any of them
}