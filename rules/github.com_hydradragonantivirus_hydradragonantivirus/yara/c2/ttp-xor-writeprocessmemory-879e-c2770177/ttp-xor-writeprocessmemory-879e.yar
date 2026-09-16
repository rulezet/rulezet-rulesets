rule TTP_XOR_WriteProcessMemory_879e {
  strings:
    $key_879e = { d0 ec [2] e2 ce [2] e4 fb [2] ca fb [2] f5 e7 }

  condition:
    any of them
}