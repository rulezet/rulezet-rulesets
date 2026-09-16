rule TTP_XOR_WriteProcessMemory_ae77 {
  strings:
    $key_ae77 = { f9 05 [2] cb 27 [2] cd 12 [2] e3 12 [2] dc 0e }

  condition:
    any of them
}