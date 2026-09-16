rule TTP_XOR_WriteProcessMemory_439e {
  strings:
    $key_439e = { 14 ec [2] 26 ce [2] 20 fb [2] 0e fb [2] 31 e7 }

  condition:
    any of them
}