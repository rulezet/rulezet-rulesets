rule TTP_XOR_WriteProcessMemory_9cbc {
  strings:
    $key_9cbc = { cb ce [2] f9 ec [2] ff d9 [2] d1 d9 [2] ee c5 }

  condition:
    any of them
}