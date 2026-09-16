rule TTP_XOR_WriteProcessMemory_ae33 {
  strings:
    $key_ae33 = { f9 41 [2] cb 63 [2] cd 56 [2] e3 56 [2] dc 4a }

  condition:
    any of them
}