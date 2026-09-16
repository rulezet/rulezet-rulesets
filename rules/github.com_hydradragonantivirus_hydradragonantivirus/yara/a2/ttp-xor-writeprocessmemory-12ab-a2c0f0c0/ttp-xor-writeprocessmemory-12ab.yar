rule TTP_XOR_WriteProcessMemory_12ab {
  strings:
    $key_12ab = { 45 d9 [2] 77 fb [2] 71 ce [2] 5f ce [2] 60 d2 }

  condition:
    any of them
}