rule TTP_XOR_WriteProcessMemory_a59e {
  strings:
    $key_a59e = { f2 ec [2] c0 ce [2] c6 fb [2] e8 fb [2] d7 e7 }

  condition:
    any of them
}