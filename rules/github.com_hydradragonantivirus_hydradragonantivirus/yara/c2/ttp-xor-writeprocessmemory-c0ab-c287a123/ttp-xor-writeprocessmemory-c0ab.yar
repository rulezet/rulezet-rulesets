rule TTP_XOR_WriteProcessMemory_c0ab {
  strings:
    $key_c0ab = { 97 d9 [2] a5 fb [2] a3 ce [2] 8d ce [2] b2 d2 }

  condition:
    any of them
}