rule TTP_XOR_WriteProcessMemory_77ab {
  strings:
    $key_77ab = { 20 d9 [2] 12 fb [2] 14 ce [2] 3a ce [2] 05 d2 }

  condition:
    any of them
}