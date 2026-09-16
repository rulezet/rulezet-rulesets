rule TTP_XOR_WriteProcessMemory_9aab {
  strings:
    $key_9aab = { cd d9 [2] ff fb [2] f9 ce [2] d7 ce [2] e8 d2 }

  condition:
    any of them
}