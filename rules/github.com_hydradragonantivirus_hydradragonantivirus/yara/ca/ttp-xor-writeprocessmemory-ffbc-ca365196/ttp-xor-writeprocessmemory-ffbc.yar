rule TTP_XOR_WriteProcessMemory_ffbc {
  strings:
    $key_ffbc = { a8 ce [2] 9a ec [2] 9c d9 [2] b2 d9 [2] 8d c5 }

  condition:
    any of them
}