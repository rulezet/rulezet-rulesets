rule TTP_XOR_WriteProcessMemory_039e {
  strings:
    $key_039e = { 54 ec [2] 66 ce [2] 60 fb [2] 4e fb [2] 71 e7 }

  condition:
    any of them
}