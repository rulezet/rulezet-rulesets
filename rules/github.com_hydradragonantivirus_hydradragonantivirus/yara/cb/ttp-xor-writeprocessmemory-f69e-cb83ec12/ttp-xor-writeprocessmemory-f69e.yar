rule TTP_XOR_WriteProcessMemory_f69e {
  strings:
    $key_f69e = { a1 ec [2] 93 ce [2] 95 fb [2] bb fb [2] 84 e7 }

  condition:
    any of them
}