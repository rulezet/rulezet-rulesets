rule TTP_XOR_WriteProcessMemory_ae71 {
  strings:
    $key_ae71 = { f9 03 [2] cb 21 [2] cd 14 [2] e3 14 [2] dc 08 }

  condition:
    any of them
}