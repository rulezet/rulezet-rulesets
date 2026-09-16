rule TTP_XOR_WriteProcessMemory_a2ab {
  strings:
    $key_a2ab = { f5 d9 [2] c7 fb [2] c1 ce [2] ef ce [2] d0 d2 }

  condition:
    any of them
}