rule TTP_XOR_WriteProcessMemory_87ab {
  strings:
    $key_87ab = { d0 d9 [2] e2 fb [2] e4 ce [2] ca ce [2] f5 d2 }

  condition:
    any of them
}