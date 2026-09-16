rule TTP_XOR_WriteProcessMemory_dabc {
  strings:
    $key_dabc = { 8d ce [2] bf ec [2] b9 d9 [2] 97 d9 [2] a8 c5 }

  condition:
    any of them
}