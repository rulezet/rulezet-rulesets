rule TTP_XOR_WriteProcessMemory_53ab {
  strings:
    $key_53ab = { 04 d9 [2] 36 fb [2] 30 ce [2] 1e ce [2] 21 d2 }

  condition:
    any of them
}