rule TTP_XOR_WriteProcessMemory_189e {
  strings:
    $key_189e = { 4f ec [2] 7d ce [2] 7b fb [2] 55 fb [2] 6a e7 }

  condition:
    any of them
}