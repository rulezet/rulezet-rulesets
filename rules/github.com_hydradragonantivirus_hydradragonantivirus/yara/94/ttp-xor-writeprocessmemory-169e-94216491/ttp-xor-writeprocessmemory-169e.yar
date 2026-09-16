rule TTP_XOR_WriteProcessMemory_169e {
  strings:
    $key_169e = { 41 ec [2] 73 ce [2] 75 fb [2] 5b fb [2] 64 e7 }

  condition:
    any of them
}