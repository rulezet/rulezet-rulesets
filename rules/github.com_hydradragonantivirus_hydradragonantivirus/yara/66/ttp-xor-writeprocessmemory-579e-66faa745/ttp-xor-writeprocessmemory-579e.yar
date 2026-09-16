rule TTP_XOR_WriteProcessMemory_579e {
  strings:
    $key_579e = { 00 ec [2] 32 ce [2] 34 fb [2] 1a fb [2] 25 e7 }

  condition:
    any of them
}