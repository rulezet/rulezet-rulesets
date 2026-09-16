rule TTP_XOR_WriteProcessMemory_f59e {
  strings:
    $key_f59e = { a2 ec [2] 90 ce [2] 96 fb [2] b8 fb [2] 87 e7 }

  condition:
    any of them
}