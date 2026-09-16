rule TTP_XOR_WriteProcessMemory_779e {
  strings:
    $key_779e = { 20 ec [2] 12 ce [2] 14 fb [2] 3a fb [2] 05 e7 }

  condition:
    any of them
}