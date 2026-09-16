rule TTP_XOR_WriteProcessMemory_ceab {
  strings:
    $key_ceab = { 99 d9 [2] ab fb [2] ad ce [2] 83 ce [2] bc d2 }

  condition:
    any of them
}