rule TTP_XOR_WriteProcessMemory_f1ab {
  strings:
    $key_f1ab = { a6 d9 [2] 94 fb [2] 92 ce [2] bc ce [2] 83 d2 }

  condition:
    any of them
}