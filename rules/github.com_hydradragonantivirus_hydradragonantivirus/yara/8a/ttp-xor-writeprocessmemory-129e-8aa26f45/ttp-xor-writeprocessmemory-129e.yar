rule TTP_XOR_WriteProcessMemory_129e {
  strings:
    $key_129e = { 45 ec [2] 77 ce [2] 71 fb [2] 5f fb [2] 60 e7 }

  condition:
    any of them
}