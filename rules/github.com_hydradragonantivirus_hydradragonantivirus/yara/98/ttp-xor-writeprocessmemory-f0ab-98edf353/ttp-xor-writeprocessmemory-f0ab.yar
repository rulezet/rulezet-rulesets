rule TTP_XOR_WriteProcessMemory_f0ab {
  strings:
    $key_f0ab = { a7 d9 [2] 95 fb [2] 93 ce [2] bd ce [2] 82 d2 }

  condition:
    any of them
}