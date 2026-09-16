rule TTP_XOR_WriteProcessMemory_73ab {
  strings:
    $key_73ab = { 24 d9 [2] 16 fb [2] 10 ce [2] 3e ce [2] 01 d2 }

  condition:
    any of them
}