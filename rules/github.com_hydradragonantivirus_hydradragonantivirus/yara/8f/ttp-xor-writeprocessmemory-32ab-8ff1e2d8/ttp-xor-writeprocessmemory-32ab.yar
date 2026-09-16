rule TTP_XOR_WriteProcessMemory_32ab {
  strings:
    $key_32ab = { 65 d9 [2] 57 fb [2] 51 ce [2] 7f ce [2] 40 d2 }

  condition:
    any of them
}