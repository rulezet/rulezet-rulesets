rule TTP_XOR_WriteProcessMemory_219e {
  strings:
    $key_219e = { 76 ec [2] 44 ce [2] 42 fb [2] 6c fb [2] 53 e7 }

  condition:
    any of them
}