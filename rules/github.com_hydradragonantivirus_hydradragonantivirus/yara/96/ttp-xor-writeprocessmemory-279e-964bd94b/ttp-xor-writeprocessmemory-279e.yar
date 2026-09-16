rule TTP_XOR_WriteProcessMemory_279e {
  strings:
    $key_279e = { 70 ec [2] 42 ce [2] 44 fb [2] 6a fb [2] 55 e7 }

  condition:
    any of them
}