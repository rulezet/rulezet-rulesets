rule TTP_XOR_WriteProcessMemory_8fab {
  strings:
    $key_8fab = { d8 d9 [2] ea fb [2] ec ce [2] c2 ce [2] fd d2 }

  condition:
    any of them
}