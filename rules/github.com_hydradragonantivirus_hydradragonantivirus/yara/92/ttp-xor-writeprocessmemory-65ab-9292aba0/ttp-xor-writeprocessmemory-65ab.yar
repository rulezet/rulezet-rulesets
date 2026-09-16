rule TTP_XOR_WriteProcessMemory_65ab {
  strings:
    $key_65ab = { 32 d9 [2] 00 fb [2] 06 ce [2] 28 ce [2] 17 d2 }

  condition:
    any of them
}