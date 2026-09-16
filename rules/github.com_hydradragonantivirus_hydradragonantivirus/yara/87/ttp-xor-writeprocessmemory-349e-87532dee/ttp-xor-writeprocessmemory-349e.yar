rule TTP_XOR_WriteProcessMemory_349e {
  strings:
    $key_349e = { 63 ec [2] 51 ce [2] 57 fb [2] 79 fb [2] 46 e7 }

  condition:
    any of them
}