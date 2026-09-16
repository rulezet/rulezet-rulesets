rule TTP_XOR_WriteProcessMemory_3a9e {
  strings:
    $key_3a9e = { 6d ec [2] 5f ce [2] 59 fb [2] 77 fb [2] 48 e7 }

  condition:
    any of them
}