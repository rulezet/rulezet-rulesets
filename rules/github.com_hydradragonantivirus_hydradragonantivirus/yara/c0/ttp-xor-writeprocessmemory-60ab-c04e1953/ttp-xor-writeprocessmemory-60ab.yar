rule TTP_XOR_WriteProcessMemory_60ab {
  strings:
    $key_60ab = { 37 d9 [2] 05 fb [2] 03 ce [2] 2d ce [2] 12 d2 }

  condition:
    any of them
}