rule TTP_XOR_WriteProcessMemory_0a9e {
  strings:
    $key_0a9e = { 5d ec [2] 6f ce [2] 69 fb [2] 47 fb [2] 78 e7 }

  condition:
    any of them
}