rule TTP_XOR_WriteProcessMemory_aaab {
  strings:
    $key_aaab = { fd d9 [2] cf fb [2] c9 ce [2] e7 ce [2] d8 d2 }

  condition:
    any of them
}