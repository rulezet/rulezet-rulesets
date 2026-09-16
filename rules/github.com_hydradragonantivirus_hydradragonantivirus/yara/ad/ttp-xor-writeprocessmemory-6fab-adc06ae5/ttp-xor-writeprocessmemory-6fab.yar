rule TTP_XOR_WriteProcessMemory_6fab {
  strings:
    $key_6fab = { 38 d9 [2] 0a fb [2] 0c ce [2] 22 ce [2] 1d d2 }

  condition:
    any of them
}