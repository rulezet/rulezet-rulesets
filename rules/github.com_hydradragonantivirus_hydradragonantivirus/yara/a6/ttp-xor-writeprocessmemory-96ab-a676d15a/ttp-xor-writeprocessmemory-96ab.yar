rule TTP_XOR_WriteProcessMemory_96ab {
  strings:
    $key_96ab = { c1 d9 [2] f3 fb [2] f5 ce [2] db ce [2] e4 d2 }

  condition:
    any of them
}