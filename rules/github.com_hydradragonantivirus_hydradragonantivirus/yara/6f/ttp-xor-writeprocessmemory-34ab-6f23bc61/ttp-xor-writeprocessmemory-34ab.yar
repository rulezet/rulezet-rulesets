rule TTP_XOR_WriteProcessMemory_34ab {
  strings:
    $key_34ab = { 63 d9 [2] 51 fb [2] 57 ce [2] 79 ce [2] 46 d2 }

  condition:
    any of them
}