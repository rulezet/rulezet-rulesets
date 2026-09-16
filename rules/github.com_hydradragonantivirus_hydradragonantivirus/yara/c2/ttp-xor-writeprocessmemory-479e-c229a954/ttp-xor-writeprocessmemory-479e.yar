rule TTP_XOR_WriteProcessMemory_479e {
  strings:
    $key_479e = { 10 ec [2] 22 ce [2] 24 fb [2] 0a fb [2] 35 e7 }

  condition:
    any of them
}