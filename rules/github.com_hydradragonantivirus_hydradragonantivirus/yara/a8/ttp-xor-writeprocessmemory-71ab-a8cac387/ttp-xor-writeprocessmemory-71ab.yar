rule TTP_XOR_WriteProcessMemory_71ab {
  strings:
    $key_71ab = { 26 d9 [2] 14 fb [2] 12 ce [2] 3c ce [2] 03 d2 }

  condition:
    any of them
}