rule TTP_XOR_WriteProcessMemory_aefa {
  strings:
    $key_aefa = { f9 88 [2] cb aa [2] cd 9f [2] e3 9f [2] dc 83 }

  condition:
    any of them
}