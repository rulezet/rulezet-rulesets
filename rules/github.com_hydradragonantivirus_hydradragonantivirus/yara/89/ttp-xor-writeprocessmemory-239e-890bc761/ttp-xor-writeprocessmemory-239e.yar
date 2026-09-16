rule TTP_XOR_WriteProcessMemory_239e {
  strings:
    $key_239e = { 74 ec [2] 46 ce [2] 40 fb [2] 6e fb [2] 51 e7 }

  condition:
    any of them
}