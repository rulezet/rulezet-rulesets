rule TTP_XOR_WriteProcessMemory_66ab {
  strings:
    $key_66ab = { 31 d9 [2] 03 fb [2] 05 ce [2] 2b ce [2] 14 d2 }

  condition:
    any of them
}