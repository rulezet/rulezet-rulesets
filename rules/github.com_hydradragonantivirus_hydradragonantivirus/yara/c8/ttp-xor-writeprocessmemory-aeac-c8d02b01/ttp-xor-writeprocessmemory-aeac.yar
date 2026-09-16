rule TTP_XOR_WriteProcessMemory_aeac {
  strings:
    $key_aeac = { f9 de [2] cb fc [2] cd c9 [2] e3 c9 [2] dc d5 }

  condition:
    any of them
}