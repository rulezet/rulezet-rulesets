rule TTP_XOR_WriteProcessMemory_31ab {
  strings:
    $key_31ab = { 66 d9 [2] 54 fb [2] 52 ce [2] 7c ce [2] 43 d2 }

  condition:
    any of them
}