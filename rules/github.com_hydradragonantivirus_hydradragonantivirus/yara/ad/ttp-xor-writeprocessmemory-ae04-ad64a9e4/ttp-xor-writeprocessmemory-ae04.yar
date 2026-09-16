rule TTP_XOR_WriteProcessMemory_ae04 {
  strings:
    $key_ae04 = { f9 76 [2] cb 54 [2] cd 61 [2] e3 61 [2] dc 7d }

  condition:
    any of them
}