rule TTP_XOR_WriteProcessMemory_40ab {
  strings:
    $key_40ab = { 17 d9 [2] 25 fb [2] 23 ce [2] 0d ce [2] 32 d2 }

  condition:
    any of them
}