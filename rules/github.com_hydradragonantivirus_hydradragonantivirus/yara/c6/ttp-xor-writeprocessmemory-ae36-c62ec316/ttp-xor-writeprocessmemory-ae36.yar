rule TTP_XOR_WriteProcessMemory_ae36 {
  strings:
    $key_ae36 = { f9 44 [2] cb 66 [2] cd 53 [2] e3 53 [2] dc 4f }

  condition:
    any of them
}