rule TTP_XOR_WriteProcessMemory_03ab {
  strings:
    $key_03ab = { 54 d9 [2] 66 fb [2] 60 ce [2] 4e ce [2] 71 d2 }

  condition:
    any of them
}