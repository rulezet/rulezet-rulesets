rule TTP_XOR_WriteProcessMemory_909e {
  strings:
    $key_909e = { c7 ec [2] f5 ce [2] f3 fb [2] dd fb [2] e2 e7 }

  condition:
    any of them
}