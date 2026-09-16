rule TTP_XOR_WriteProcessMemory_ae62 {
  strings:
    $key_ae62 = { f9 10 [2] cb 32 [2] cd 07 [2] e3 07 [2] dc 1b }

  condition:
    any of them
}