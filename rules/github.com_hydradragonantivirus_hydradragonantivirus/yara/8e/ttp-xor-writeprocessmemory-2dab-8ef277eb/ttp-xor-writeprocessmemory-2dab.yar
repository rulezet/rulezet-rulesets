rule TTP_XOR_WriteProcessMemory_2dab {
  strings:
    $key_2dab = { 7a d9 [2] 48 fb [2] 4e ce [2] 60 ce [2] 5f d2 }

  condition:
    any of them
}