rule TTP_XOR_WriteProcessMemory_6bab {
  strings:
    $key_6bab = { 3c d9 [2] 0e fb [2] 08 ce [2] 26 ce [2] 19 d2 }

  condition:
    any of them
}