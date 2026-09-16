rule TTP_XOR_WriteProcessMemory_839e {
  strings:
    $key_839e = { d4 ec [2] e6 ce [2] e0 fb [2] ce fb [2] f1 e7 }

  condition:
    any of them
}