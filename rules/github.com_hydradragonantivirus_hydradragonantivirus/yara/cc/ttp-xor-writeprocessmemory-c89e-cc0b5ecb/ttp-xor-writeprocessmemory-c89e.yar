rule TTP_XOR_WriteProcessMemory_c89e {
  strings:
    $key_c89e = { 9f ec [2] ad ce [2] ab fb [2] 85 fb [2] ba e7 }

  condition:
    any of them
}