rule TTP_XOR_WriteProcessMemory_1fbc {
  strings:
    $key_1fbc = { 48 ce [2] 7a ec [2] 7c d9 [2] 52 d9 [2] 6d c5 }

  condition:
    any of them
}