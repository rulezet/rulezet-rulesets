rule TTP_XOR_WriteProcessMemory_7eab {
  strings:
    $key_7eab = { 29 d9 [2] 1b fb [2] 1d ce [2] 33 ce [2] 0c d2 }

  condition:
    any of them
}