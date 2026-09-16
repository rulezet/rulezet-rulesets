rule TTP_XOR_WriteProcessMemory_51ab {
  strings:
    $key_51ab = { 06 d9 [2] 34 fb [2] 32 ce [2] 1c ce [2] 23 d2 }

  condition:
    any of them
}