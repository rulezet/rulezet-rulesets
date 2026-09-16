rule TTP_XOR_WriteProcessMemory_c59e {
  strings:
    $key_c59e = { 92 ec [2] a0 ce [2] a6 fb [2] 88 fb [2] b7 e7 }

  condition:
    any of them
}