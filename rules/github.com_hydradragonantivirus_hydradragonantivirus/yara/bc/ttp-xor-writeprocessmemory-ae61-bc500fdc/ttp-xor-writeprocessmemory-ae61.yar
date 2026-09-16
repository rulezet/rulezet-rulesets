rule TTP_XOR_WriteProcessMemory_ae61 {
  strings:
    $key_ae61 = { f9 13 [2] cb 31 [2] cd 04 [2] e3 04 [2] dc 18 }

  condition:
    any of them
}