rule TTP_XOR_WriteProcessMemory_88ab {
  strings:
    $key_88ab = { df d9 [2] ed fb [2] eb ce [2] c5 ce [2] fa d2 }

  condition:
    any of them
}