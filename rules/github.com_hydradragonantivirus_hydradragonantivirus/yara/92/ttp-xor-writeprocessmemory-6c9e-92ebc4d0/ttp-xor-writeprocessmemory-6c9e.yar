rule TTP_XOR_WriteProcessMemory_6c9e {
  strings:
    $key_6c9e = { 3b ec [2] 09 ce [2] 0f fb [2] 21 fb [2] 1e e7 }

  condition:
    any of them
}