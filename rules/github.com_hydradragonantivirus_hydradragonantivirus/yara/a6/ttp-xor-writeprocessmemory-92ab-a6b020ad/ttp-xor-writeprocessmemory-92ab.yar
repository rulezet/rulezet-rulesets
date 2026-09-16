rule TTP_XOR_WriteProcessMemory_92ab {
  strings:
    $key_92ab = { c5 d9 [2] f7 fb [2] f1 ce [2] df ce [2] e0 d2 }

  condition:
    any of them
}