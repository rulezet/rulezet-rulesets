rule TTP_XOR_WriteProcessMemory_fa9e {
  strings:
    $key_fa9e = { ad ec [2] 9f ce [2] 99 fb [2] b7 fb [2] 88 e7 }

  condition:
    any of them
}