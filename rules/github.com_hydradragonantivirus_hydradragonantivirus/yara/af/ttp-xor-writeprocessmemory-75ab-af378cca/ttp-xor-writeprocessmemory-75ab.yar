rule TTP_XOR_WriteProcessMemory_75ab {
  strings:
    $key_75ab = { 22 d9 [2] 10 fb [2] 16 ce [2] 38 ce [2] 07 d2 }

  condition:
    any of them
}