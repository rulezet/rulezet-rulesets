rule TTP_XOR_WriteProcessMemory_46ab {
  strings:
    $key_46ab = { 11 d9 [2] 23 fb [2] 25 ce [2] 0b ce [2] 34 d2 }

  condition:
    any of them
}