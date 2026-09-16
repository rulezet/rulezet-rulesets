rule TTP_XOR_WriteProcessMemory_7fbc {
  strings:
    $key_7fbc = { 28 ce [2] 1a ec [2] 1c d9 [2] 32 d9 [2] 0d c5 }

  condition:
    any of them
}