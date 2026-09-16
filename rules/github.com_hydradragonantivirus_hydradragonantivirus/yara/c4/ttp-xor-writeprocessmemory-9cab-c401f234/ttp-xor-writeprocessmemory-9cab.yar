rule TTP_XOR_WriteProcessMemory_9cab {
  strings:
    $key_9cab = { cb d9 [2] f9 fb [2] ff ce [2] d1 ce [2] ee d2 }

  condition:
    any of them
}