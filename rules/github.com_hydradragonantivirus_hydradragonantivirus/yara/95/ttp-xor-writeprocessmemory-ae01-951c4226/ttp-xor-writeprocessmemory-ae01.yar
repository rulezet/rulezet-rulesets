rule TTP_XOR_WriteProcessMemory_ae01 {
  strings:
    $key_ae01 = { f9 73 [2] cb 51 [2] cd 64 [2] e3 64 [2] dc 78 }

  condition:
    any of them
}