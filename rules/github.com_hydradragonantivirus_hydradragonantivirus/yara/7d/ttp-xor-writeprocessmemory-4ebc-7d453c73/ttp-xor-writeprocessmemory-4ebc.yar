rule TTP_XOR_WriteProcessMemory_4ebc {
  strings:
    $key_4ebc = { 19 ce [2] 2b ec [2] 2d d9 [2] 03 d9 [2] 3c c5 }

  condition:
    any of them
}