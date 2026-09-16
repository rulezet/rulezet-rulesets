rule TTP_XOR_WriteProcessMemory_ae31 {
  strings:
    $key_ae31 = { f9 43 [2] cb 61 [2] cd 54 [2] e3 54 [2] dc 48 }

  condition:
    any of them
}