rule TTP_XOR_WriteProcessMemory_64ab {
  strings:
    $key_64ab = { 33 d9 [2] 01 fb [2] 07 ce [2] 29 ce [2] 16 d2 }

  condition:
    any of them
}