rule TTP_XOR_WriteProcessMemory_559e {
  strings:
    $key_559e = { 02 ec [2] 30 ce [2] 36 fb [2] 18 fb [2] 27 e7 }

  condition:
    any of them
}