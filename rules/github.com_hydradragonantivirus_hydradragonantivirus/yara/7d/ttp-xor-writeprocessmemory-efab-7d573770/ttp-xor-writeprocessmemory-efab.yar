rule TTP_XOR_WriteProcessMemory_efab {
  strings:
    $key_efab = { b8 d9 [2] 8a fb [2] 8c ce [2] a2 ce [2] 9d d2 }

  condition:
    any of them
}