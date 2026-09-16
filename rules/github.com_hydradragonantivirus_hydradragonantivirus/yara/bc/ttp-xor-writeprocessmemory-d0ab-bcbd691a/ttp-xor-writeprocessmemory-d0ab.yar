rule TTP_XOR_WriteProcessMemory_d0ab {
  strings:
    $key_d0ab = { 87 d9 [2] b5 fb [2] b3 ce [2] 9d ce [2] a2 d2 }

  condition:
    any of them
}