rule TTP_XOR_WriteProcessMemory_d2ab {
  strings:
    $key_d2ab = { 85 d9 [2] b7 fb [2] b1 ce [2] 9f ce [2] a0 d2 }

  condition:
    any of them
}