rule TTP_XOR_WriteProcessMemory_6a9e {
  strings:
    $key_6a9e = { 3d ec [2] 0f ce [2] 09 fb [2] 27 fb [2] 18 e7 }

  condition:
    any of them
}