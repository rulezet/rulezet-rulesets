rule TTP_XOR_WriteProcessMemory_8c9e {
  strings:
    $key_8c9e = { db ec [2] e9 ce [2] ef fb [2] c1 fb [2] fe e7 }

  condition:
    any of them
}