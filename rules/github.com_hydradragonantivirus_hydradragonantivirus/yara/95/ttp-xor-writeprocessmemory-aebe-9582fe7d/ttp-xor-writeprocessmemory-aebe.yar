rule TTP_XOR_WriteProcessMemory_aebe {
  strings:
    $key_aebe = { f9 cc [2] cb ee [2] cd db [2] e3 db [2] dc c7 }

  condition:
    any of them
}