rule TTP_XOR_WriteProcessMemory_cdab {
  strings:
    $key_cdab = { 9a d9 [2] a8 fb [2] ae ce [2] 80 ce [2] bf d2 }

  condition:
    any of them
}