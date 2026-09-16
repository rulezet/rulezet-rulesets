rule TTP_XOR_WriteProcessMemory_e49e {
  strings:
    $key_e49e = { b3 ec [2] 81 ce [2] 87 fb [2] a9 fb [2] 96 e7 }

  condition:
    any of them
}