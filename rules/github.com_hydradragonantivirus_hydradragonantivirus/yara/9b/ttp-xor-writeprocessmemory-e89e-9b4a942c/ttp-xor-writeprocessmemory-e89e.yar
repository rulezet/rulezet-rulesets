rule TTP_XOR_WriteProcessMemory_e89e {
  strings:
    $key_e89e = { bf ec [2] 8d ce [2] 8b fb [2] a5 fb [2] 9a e7 }

  condition:
    any of them
}