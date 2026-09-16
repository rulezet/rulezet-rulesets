rule TTP_XOR_WriteProcessMemory_ea9e {
  strings:
    $key_ea9e = { bd ec [2] 8f ce [2] 89 fb [2] a7 fb [2] 98 e7 }

  condition:
    any of them
}