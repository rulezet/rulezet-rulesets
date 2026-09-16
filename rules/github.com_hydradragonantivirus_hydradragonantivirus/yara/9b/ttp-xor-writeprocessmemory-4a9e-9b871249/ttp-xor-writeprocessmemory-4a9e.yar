rule TTP_XOR_WriteProcessMemory_4a9e {
  strings:
    $key_4a9e = { 1d ec [2] 2f ce [2] 29 fb [2] 07 fb [2] 38 e7 }

  condition:
    any of them
}