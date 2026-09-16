rule TTP_XOR_WriteProcessMemory_ae46 {
  strings:
    $key_ae46 = { f9 34 [2] cb 16 [2] cd 23 [2] e3 23 [2] dc 3f }

  condition:
    any of them
}