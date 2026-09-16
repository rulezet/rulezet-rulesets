rule TTP_XOR_WriteProcessMemory_70ab {
  strings:
    $key_70ab = { 27 d9 [2] 15 fb [2] 13 ce [2] 3d ce [2] 02 d2 }

  condition:
    any of them
}