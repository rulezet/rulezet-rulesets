rule TTP_XOR_WriteProcessMemory_f79e {
  strings:
    $key_f79e = { a0 ec [2] 92 ce [2] 94 fb [2] ba fb [2] 85 e7 }

  condition:
    any of them
}