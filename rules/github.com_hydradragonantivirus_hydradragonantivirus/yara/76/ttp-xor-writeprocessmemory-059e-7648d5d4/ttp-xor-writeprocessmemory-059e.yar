rule TTP_XOR_WriteProcessMemory_059e {
  strings:
    $key_059e = { 52 ec [2] 60 ce [2] 66 fb [2] 48 fb [2] 77 e7 }

  condition:
    any of them
}