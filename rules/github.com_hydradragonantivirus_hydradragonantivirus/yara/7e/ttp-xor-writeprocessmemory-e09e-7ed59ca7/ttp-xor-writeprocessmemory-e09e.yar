rule TTP_XOR_WriteProcessMemory_e09e {
  strings:
    $key_e09e = { b7 ec [2] 85 ce [2] 83 fb [2] ad fb [2] 92 e7 }

  condition:
    any of them
}