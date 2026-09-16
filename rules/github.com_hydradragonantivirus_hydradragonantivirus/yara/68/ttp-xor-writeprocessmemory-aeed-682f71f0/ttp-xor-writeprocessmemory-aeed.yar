rule TTP_XOR_WriteProcessMemory_aeed {
  strings:
    $key_aeed = { f9 9f [2] cb bd [2] cd 88 [2] e3 88 [2] dc 94 }

  condition:
    any of them
}