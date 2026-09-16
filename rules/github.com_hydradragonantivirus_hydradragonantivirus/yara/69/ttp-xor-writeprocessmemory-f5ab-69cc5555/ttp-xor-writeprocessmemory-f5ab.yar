rule TTP_XOR_WriteProcessMemory_f5ab {
  strings:
    $key_f5ab = { a2 d9 [2] 90 fb [2] 96 ce [2] b8 ce [2] 87 d2 }

  condition:
    any of them
}