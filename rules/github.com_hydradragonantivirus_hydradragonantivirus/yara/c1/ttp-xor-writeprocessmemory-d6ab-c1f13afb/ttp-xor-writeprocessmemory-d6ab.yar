rule TTP_XOR_WriteProcessMemory_d6ab {
  strings:
    $key_d6ab = { 81 d9 [2] b3 fb [2] b5 ce [2] 9b ce [2] a4 d2 }

  condition:
    any of them
}