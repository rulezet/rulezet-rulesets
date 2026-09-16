rule TTP_XOR_WriteProcessMemory_519e {
  strings:
    $key_519e = { 06 ec [2] 34 ce [2] 32 fb [2] 1c fb [2] 23 e7 }

  condition:
    any of them
}