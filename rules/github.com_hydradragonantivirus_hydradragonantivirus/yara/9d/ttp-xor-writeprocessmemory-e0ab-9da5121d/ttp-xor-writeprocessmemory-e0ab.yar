rule TTP_XOR_WriteProcessMemory_e0ab {
  strings:
    $key_e0ab = { b7 d9 [2] 85 fb [2] 83 ce [2] ad ce [2] 92 d2 }

  condition:
    any of them
}