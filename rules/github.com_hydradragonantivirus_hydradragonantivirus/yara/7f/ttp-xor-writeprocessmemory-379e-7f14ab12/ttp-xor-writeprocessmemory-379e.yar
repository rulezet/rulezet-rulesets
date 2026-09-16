rule TTP_XOR_WriteProcessMemory_379e {
  strings:
    $key_379e = { 60 ec [2] 52 ce [2] 54 fb [2] 7a fb [2] 45 e7 }

  condition:
    any of them
}