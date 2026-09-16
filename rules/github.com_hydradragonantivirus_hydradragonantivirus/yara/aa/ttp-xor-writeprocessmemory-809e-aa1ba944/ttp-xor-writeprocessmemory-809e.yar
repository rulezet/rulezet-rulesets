rule TTP_XOR_WriteProcessMemory_809e {
  strings:
    $key_809e = { d7 ec [2] e5 ce [2] e3 fb [2] cd fb [2] f2 e7 }

  condition:
    any of them
}