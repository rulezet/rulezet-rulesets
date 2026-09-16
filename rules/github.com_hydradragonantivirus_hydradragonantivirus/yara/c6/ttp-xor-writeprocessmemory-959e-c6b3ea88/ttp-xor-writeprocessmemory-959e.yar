rule TTP_XOR_WriteProcessMemory_959e {
  strings:
    $key_959e = { c2 ec [2] f0 ce [2] f6 fb [2] d8 fb [2] e7 e7 }

  condition:
    any of them
}