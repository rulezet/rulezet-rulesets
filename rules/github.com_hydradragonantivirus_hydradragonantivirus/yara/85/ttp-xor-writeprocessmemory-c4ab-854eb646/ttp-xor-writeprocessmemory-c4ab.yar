rule TTP_XOR_WriteProcessMemory_c4ab {
  strings:
    $key_c4ab = { 93 d9 [2] a1 fb [2] a7 ce [2] 89 ce [2] b6 d2 }

  condition:
    any of them
}