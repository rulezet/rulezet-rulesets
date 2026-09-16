rule TTP_XOR_WriteProcessMemory_d7ab {
  strings:
    $key_d7ab = { 80 d9 [2] b2 fb [2] b4 ce [2] 9a ce [2] a5 d2 }

  condition:
    any of them
}