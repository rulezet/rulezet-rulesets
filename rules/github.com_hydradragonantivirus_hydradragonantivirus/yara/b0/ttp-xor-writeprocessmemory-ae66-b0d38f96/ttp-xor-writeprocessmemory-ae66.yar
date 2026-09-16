rule TTP_XOR_WriteProcessMemory_ae66 {
  strings:
    $key_ae66 = { f9 14 [2] cb 36 [2] cd 03 [2] e3 03 [2] dc 1f }

  condition:
    any of them
}