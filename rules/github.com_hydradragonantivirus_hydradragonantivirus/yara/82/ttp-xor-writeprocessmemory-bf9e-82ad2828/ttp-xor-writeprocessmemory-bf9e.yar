rule TTP_XOR_WriteProcessMemory_bf9e {
  strings:
    $key_bf9e = { e8 ec [2] da ce [2] dc fb [2] f2 fb [2] cd e7 }

  condition:
    any of them
}