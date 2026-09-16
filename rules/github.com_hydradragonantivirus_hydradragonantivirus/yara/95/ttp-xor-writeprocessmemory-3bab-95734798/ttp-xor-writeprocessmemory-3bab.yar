rule TTP_XOR_WriteProcessMemory_3bab {
  strings:
    $key_3bab = { 6c d9 [2] 5e fb [2] 58 ce [2] 76 ce [2] 49 d2 }

  condition:
    any of them
}