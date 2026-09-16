rule TTP_XOR_WriteProcessMemory_7a9e {
  strings:
    $key_7a9e = { 2d ec [2] 1f ce [2] 19 fb [2] 37 fb [2] 08 e7 }

  condition:
    any of them
}