rule TTP_XOR_WriteProcessMemory_569e {
  strings:
    $key_569e = { 01 ec [2] 33 ce [2] 35 fb [2] 1b fb [2] 24 e7 }

  condition:
    any of them
}