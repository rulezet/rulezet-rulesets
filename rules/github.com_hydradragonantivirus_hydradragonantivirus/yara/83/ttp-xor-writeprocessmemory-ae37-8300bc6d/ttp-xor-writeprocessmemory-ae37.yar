rule TTP_XOR_WriteProcessMemory_ae37 {
  strings:
    $key_ae37 = { f9 45 [2] cb 67 [2] cd 52 [2] e3 52 [2] dc 4e }

  condition:
    any of them
}