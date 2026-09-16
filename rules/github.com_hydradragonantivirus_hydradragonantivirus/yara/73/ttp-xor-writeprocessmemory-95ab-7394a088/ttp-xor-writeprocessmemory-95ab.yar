rule TTP_XOR_WriteProcessMemory_95ab {
  strings:
    $key_95ab = { c2 d9 [2] f0 fb [2] f6 ce [2] d8 ce [2] e7 d2 }

  condition:
    any of them
}