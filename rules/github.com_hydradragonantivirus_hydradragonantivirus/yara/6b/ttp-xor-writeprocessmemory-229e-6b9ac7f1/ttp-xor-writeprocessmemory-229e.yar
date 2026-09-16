rule TTP_XOR_WriteProcessMemory_229e {
  strings:
    $key_229e = { 75 ec [2] 47 ce [2] 41 fb [2] 6f fb [2] 50 e7 }

  condition:
    any of them
}