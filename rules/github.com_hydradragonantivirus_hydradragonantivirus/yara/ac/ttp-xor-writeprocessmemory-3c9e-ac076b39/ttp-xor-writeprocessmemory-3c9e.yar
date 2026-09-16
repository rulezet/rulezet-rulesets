rule TTP_XOR_WriteProcessMemory_3c9e {
  strings:
    $key_3c9e = { 6b ec [2] 59 ce [2] 5f fb [2] 71 fb [2] 4e e7 }

  condition:
    any of them
}