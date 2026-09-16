rule TTP_XOR_WriteProcessMemory_a7ab {
  strings:
    $key_a7ab = { f0 d9 [2] c2 fb [2] c4 ce [2] ea ce [2] d5 d2 }

  condition:
    any of them
}