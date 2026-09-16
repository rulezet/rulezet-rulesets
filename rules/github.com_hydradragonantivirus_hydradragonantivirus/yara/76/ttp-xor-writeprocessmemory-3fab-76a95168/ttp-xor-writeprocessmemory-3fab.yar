rule TTP_XOR_WriteProcessMemory_3fab {
  strings:
    $key_3fab = { 68 d9 [2] 5a fb [2] 5c ce [2] 72 ce [2] 4d d2 }

  condition:
    any of them
}