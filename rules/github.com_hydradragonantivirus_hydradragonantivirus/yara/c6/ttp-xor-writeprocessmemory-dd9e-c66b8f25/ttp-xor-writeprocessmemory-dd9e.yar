rule TTP_XOR_WriteProcessMemory_dd9e {
  strings:
    $key_dd9e = { 8a ec [2] b8 ce [2] be fb [2] 90 fb [2] af e7 }

  condition:
    any of them
}