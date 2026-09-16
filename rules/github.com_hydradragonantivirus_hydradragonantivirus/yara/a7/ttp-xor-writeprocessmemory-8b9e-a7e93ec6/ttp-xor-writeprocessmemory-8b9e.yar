rule TTP_XOR_WriteProcessMemory_8b9e {
  strings:
    $key_8b9e = { dc ec [2] ee ce [2] e8 fb [2] c6 fb [2] f9 e7 }

  condition:
    any of them
}