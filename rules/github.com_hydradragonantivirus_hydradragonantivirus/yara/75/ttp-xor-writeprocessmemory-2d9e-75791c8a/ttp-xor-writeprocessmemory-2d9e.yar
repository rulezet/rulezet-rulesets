rule TTP_XOR_WriteProcessMemory_2d9e {
  strings:
    $key_2d9e = { 7a ec [2] 48 ce [2] 4e fb [2] 60 fb [2] 5f e7 }

  condition:
    any of them
}