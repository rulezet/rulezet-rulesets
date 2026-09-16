rule TTP_XOR_WriteProcessMemory_a4ab {
  strings:
    $key_a4ab = { f3 d9 [2] c1 fb [2] c7 ce [2] e9 ce [2] d6 d2 }

  condition:
    any of them
}