rule TTP_XOR_WriteProcessMemory_849e {
  strings:
    $key_849e = { d3 ec [2] e1 ce [2] e7 fb [2] c9 fb [2] f6 e7 }

  condition:
    any of them
}