rule TTP_XOR_WriteProcessMemory_dcab {
  strings:
    $key_dcab = { 8b d9 [2] b9 fb [2] bf ce [2] 91 ce [2] ae d2 }

  condition:
    any of them
}