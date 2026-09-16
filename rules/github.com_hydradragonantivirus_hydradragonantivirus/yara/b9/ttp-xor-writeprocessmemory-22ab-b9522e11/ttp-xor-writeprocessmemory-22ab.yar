rule TTP_XOR_WriteProcessMemory_22ab {
  strings:
    $key_22ab = { 75 d9 [2] 47 fb [2] 41 ce [2] 6f ce [2] 50 d2 }

  condition:
    any of them
}