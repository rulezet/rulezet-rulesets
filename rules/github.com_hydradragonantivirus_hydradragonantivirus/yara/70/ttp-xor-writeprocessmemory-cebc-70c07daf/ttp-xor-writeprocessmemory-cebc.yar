rule TTP_XOR_WriteProcessMemory_cebc {
  strings:
    $key_cebc = { 99 ce [2] ab ec [2] ad d9 [2] 83 d9 [2] bc c5 }

  condition:
    any of them
}