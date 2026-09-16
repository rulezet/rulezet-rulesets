rule TTP_XOR_WriteProcessMemory_42ab {
  strings:
    $key_42ab = { 15 d9 [2] 27 fb [2] 21 ce [2] 0f ce [2] 30 d2 }

  condition:
    any of them
}