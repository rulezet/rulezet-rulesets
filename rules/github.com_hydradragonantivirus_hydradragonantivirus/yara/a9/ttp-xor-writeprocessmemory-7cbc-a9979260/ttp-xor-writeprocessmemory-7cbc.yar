rule TTP_XOR_WriteProcessMemory_7cbc {
  strings:
    $key_7cbc = { 2b ce [2] 19 ec [2] 1f d9 [2] 31 d9 [2] 0e c5 }

  condition:
    any of them
}