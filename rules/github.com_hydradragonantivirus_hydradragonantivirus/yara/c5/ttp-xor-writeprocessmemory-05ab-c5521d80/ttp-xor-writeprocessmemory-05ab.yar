rule TTP_XOR_WriteProcessMemory_05ab {
  strings:
    $key_05ab = { 52 d9 [2] 60 fb [2] 66 ce [2] 48 ce [2] 77 d2 }

  condition:
    any of them
}