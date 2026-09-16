rule TTP_XOR_WriteProcessMemory_febc {
  strings:
    $key_febc = { a9 ce [2] 9b ec [2] 9d d9 [2] b3 d9 [2] 8c c5 }

  condition:
    any of them
}