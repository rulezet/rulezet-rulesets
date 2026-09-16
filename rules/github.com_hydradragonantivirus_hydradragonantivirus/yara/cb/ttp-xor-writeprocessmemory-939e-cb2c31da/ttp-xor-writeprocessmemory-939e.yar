rule TTP_XOR_WriteProcessMemory_939e {
  strings:
    $key_939e = { c4 ec [2] f6 ce [2] f0 fb [2] de fb [2] e1 e7 }

  condition:
    any of them
}