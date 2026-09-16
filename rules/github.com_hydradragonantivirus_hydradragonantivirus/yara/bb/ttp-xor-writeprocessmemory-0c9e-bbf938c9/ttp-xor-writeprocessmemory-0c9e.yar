rule TTP_XOR_WriteProcessMemory_0c9e {
  strings:
    $key_0c9e = { 5b ec [2] 69 ce [2] 6f fb [2] 41 fb [2] 7e e7 }

  condition:
    any of them
}