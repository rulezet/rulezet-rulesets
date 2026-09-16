rule TTP_XOR_WriteProcessMemory_ae59 {
  strings:
    $key_ae59 = { f9 2b [2] cb 09 [2] cd 3c [2] e3 3c [2] dc 20 }

  condition:
    any of them
}