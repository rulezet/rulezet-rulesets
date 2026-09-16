rule TTP_XOR_WriteProcessMemory_dfbc {
  strings:
    $key_dfbc = { 88 ce [2] ba ec [2] bc d9 [2] 92 d9 [2] ad c5 }

  condition:
    any of them
}