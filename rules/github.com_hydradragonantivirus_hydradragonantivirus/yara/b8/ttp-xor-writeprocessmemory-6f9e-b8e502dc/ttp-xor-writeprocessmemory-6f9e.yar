rule TTP_XOR_WriteProcessMemory_6f9e {
  strings:
    $key_6f9e = { 38 ec [2] 0a ce [2] 0c fb [2] 22 fb [2] 1d e7 }

  condition:
    any of them
}