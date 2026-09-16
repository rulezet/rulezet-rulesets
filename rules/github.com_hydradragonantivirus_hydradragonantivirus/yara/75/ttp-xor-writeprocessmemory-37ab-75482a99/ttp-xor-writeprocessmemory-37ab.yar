rule TTP_XOR_WriteProcessMemory_37ab {
  strings:
    $key_37ab = { 60 d9 [2] 52 fb [2] 54 ce [2] 7a ce [2] 45 d2 }

  condition:
    any of them
}