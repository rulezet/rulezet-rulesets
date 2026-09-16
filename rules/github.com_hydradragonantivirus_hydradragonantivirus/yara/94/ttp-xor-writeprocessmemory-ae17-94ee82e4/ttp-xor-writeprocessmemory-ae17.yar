rule TTP_XOR_WriteProcessMemory_ae17 {
  strings:
    $key_ae17 = { f9 65 [2] cb 47 [2] cd 72 [2] e3 72 [2] dc 6e }

  condition:
    any of them
}