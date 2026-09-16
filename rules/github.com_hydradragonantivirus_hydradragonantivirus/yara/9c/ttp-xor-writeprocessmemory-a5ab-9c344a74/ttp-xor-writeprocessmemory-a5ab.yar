rule TTP_XOR_WriteProcessMemory_a5ab {
  strings:
    $key_a5ab = { f2 d9 [2] c0 fb [2] c6 ce [2] e8 ce [2] d7 d2 }

  condition:
    any of them
}