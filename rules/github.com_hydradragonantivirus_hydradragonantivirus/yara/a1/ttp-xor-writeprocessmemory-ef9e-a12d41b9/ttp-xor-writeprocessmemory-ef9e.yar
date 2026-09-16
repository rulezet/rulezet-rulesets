rule TTP_XOR_WriteProcessMemory_ef9e {
  strings:
    $key_ef9e = { b8 ec [2] 8a ce [2] 8c fb [2] a2 fb [2] 9d e7 }

  condition:
    any of them
}