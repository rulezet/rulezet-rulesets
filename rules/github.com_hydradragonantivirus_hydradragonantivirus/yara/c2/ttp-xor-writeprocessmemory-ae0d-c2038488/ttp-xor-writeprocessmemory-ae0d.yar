rule TTP_XOR_WriteProcessMemory_ae0d {
  strings:
    $key_ae0d = { f9 7f [2] cb 5d [2] cd 68 [2] e3 68 [2] dc 74 }

  condition:
    any of them
}