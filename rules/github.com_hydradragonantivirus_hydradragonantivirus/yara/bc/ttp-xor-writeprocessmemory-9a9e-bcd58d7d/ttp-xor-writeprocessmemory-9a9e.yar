rule TTP_XOR_WriteProcessMemory_9a9e {
  strings:
    $key_9a9e = { cd ec [2] ff ce [2] f9 fb [2] d7 fb [2] e8 e7 }

  condition:
    any of them
}