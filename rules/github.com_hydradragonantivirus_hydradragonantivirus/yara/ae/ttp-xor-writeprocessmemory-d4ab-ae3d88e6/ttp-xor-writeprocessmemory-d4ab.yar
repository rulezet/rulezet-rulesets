rule TTP_XOR_WriteProcessMemory_d4ab {
  strings:
    $key_d4ab = { 83 d9 [2] b1 fb [2] b7 ce [2] 99 ce [2] a6 d2 }

  condition:
    any of them
}