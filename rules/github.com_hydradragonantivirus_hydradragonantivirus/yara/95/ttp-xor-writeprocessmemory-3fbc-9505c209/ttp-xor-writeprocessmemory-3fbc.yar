rule TTP_XOR_WriteProcessMemory_3fbc {
  strings:
    $key_3fbc = { 68 ce [2] 5a ec [2] 5c d9 [2] 72 d9 [2] 4d c5 }

  condition:
    any of them
}