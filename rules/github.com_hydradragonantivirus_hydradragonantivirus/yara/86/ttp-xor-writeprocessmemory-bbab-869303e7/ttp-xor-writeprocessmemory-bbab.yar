rule TTP_XOR_WriteProcessMemory_bbab {
  strings:
    $key_bbab = { ec d9 [2] de fb [2] d8 ce [2] f6 ce [2] c9 d2 }

  condition:
    any of them
}