rule TTP_XOR_WriteProcessMemory_dfab {
  strings:
    $key_dfab = { 88 d9 [2] ba fb [2] bc ce [2] 92 ce [2] ad d2 }

  condition:
    any of them
}