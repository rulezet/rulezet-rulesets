rule TTP_XOR_WriteProcessMemory_e5ab {
  strings:
    $key_e5ab = { b2 d9 [2] 80 fb [2] 86 ce [2] a8 ce [2] 97 d2 }

  condition:
    any of them
}