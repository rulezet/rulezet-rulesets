rule TTP_XOR_WriteProcessMemory_aeea {
  strings:
    $key_aeea = { f9 98 [2] cb ba [2] cd 8f [2] e3 8f [2] dc 93 }

  condition:
    any of them
}