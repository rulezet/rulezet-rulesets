rule TTP_XOR_WriteProcessMemory_80ab {
  strings:
    $key_80ab = { d7 d9 [2] e5 fb [2] e3 ce [2] cd ce [2] f2 d2 }

  condition:
    any of them
}