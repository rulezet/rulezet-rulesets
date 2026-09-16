rule TTP_XOR_WriteProcessMemory_2b9e {
  strings:
    $key_2b9e = { 7c ec [2] 4e ce [2] 48 fb [2] 66 fb [2] 59 e7 }

  condition:
    any of them
}