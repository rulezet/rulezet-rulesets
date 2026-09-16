rule TTP_XOR_WriteProcessMemory_ae16 {
  strings:
    $key_ae16 = { f9 64 [2] cb 46 [2] cd 73 [2] e3 73 [2] dc 6f }

  condition:
    any of them
}