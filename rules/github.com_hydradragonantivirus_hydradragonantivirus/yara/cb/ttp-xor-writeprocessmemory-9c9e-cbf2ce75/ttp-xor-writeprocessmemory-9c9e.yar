rule TTP_XOR_WriteProcessMemory_9c9e {
  strings:
    $key_9c9e = { cb ec [2] f9 ce [2] ff fb [2] d1 fb [2] ee e7 }

  condition:
    any of them
}