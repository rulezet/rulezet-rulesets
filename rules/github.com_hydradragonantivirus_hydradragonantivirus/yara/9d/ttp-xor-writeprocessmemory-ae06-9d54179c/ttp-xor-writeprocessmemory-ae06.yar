rule TTP_XOR_WriteProcessMemory_ae06 {
  strings:
    $key_ae06 = { f9 74 [2] cb 56 [2] cd 63 [2] e3 63 [2] dc 7f }

  condition:
    any of them
}