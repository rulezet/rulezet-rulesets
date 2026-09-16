rule TTP_XOR_WriteProcessMemory_ae03 {
  strings:
    $key_ae03 = { f9 71 [2] cb 53 [2] cd 66 [2] e3 66 [2] dc 7a }

  condition:
    any of them
}