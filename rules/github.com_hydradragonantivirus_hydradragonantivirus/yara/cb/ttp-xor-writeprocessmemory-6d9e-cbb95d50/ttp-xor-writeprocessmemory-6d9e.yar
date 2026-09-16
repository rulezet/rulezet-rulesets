rule TTP_XOR_WriteProcessMemory_6d9e {
  strings:
    $key_6d9e = { 3a ec [2] 08 ce [2] 0e fb [2] 20 fb [2] 1f e7 }

  condition:
    any of them
}