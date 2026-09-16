rule TTP_XOR_WriteProcessMemory_ae47 {
  strings:
    $key_ae47 = { f9 35 [2] cb 17 [2] cd 22 [2] e3 22 [2] dc 3e }

  condition:
    any of them
}