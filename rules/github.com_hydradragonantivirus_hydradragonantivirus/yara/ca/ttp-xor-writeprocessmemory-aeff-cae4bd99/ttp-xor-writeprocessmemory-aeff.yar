rule TTP_XOR_WriteProcessMemory_aeff {
  strings:
    $key_aeff = { f9 8d [2] cb af [2] cd 9a [2] e3 9a [2] dc 86 }

  condition:
    any of them
}