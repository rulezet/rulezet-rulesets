rule TTP_XOR_WriteProcessMemory_649e {
  strings:
    $key_649e = { 33 ec [2] 01 ce [2] 07 fb [2] 29 fb [2] 16 e7 }

  condition:
    any of them
}