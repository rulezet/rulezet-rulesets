rule TTP_XOR_WriteProcessMemory_819e {
  strings:
    $key_819e = { d6 ec [2] e4 ce [2] e2 fb [2] cc fb [2] f3 e7 }

  condition:
    any of them
}