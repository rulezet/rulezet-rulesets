rule TTP_XOR_WriteProcessMemory_119e {
  strings:
    $key_119e = { 46 ec [2] 74 ce [2] 72 fb [2] 5c fb [2] 63 e7 }

  condition:
    any of them
}