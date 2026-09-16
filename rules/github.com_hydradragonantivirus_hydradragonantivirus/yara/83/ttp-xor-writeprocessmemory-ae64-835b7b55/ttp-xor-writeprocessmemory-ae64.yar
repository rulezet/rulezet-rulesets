rule TTP_XOR_WriteProcessMemory_ae64 {
  strings:
    $key_ae64 = { f9 16 [2] cb 34 [2] cd 01 [2] e3 01 [2] dc 1d }

  condition:
    any of them
}