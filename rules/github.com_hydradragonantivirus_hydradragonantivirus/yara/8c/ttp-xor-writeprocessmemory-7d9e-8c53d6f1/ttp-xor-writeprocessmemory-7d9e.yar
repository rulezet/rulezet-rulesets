rule TTP_XOR_WriteProcessMemory_7d9e {
  strings:
    $key_7d9e = { 2a ec [2] 18 ce [2] 1e fb [2] 30 fb [2] 0f e7 }

  condition:
    any of them
}