rule TTP_XOR_WriteProcessMemory_949e {
  strings:
    $key_949e = { c3 ec [2] f1 ce [2] f7 fb [2] d9 fb [2] e6 e7 }

  condition:
    any of them
}