rule TTP_XOR_WriteProcessMemory_4d9e {
  strings:
    $key_4d9e = { 1a ec [2] 28 ce [2] 2e fb [2] 00 fb [2] 3f e7 }

  condition:
    any of them
}