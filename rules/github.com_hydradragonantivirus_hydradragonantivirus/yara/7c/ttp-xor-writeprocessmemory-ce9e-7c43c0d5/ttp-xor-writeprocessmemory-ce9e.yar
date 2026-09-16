rule TTP_XOR_WriteProcessMemory_ce9e {
  strings:
    $key_ce9e = { 99 ec [2] ab ce [2] ad fb [2] 83 fb [2] bc e7 }

  condition:
    any of them
}