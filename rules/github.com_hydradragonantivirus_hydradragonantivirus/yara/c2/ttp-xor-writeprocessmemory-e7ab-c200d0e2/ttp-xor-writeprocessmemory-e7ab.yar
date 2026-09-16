rule TTP_XOR_WriteProcessMemory_e7ab {
  strings:
    $key_e7ab = { b0 d9 [2] 82 fb [2] 84 ce [2] aa ce [2] 95 d2 }

  condition:
    any of them
}