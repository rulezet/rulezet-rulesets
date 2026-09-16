rule TTP_XOR_WriteProcessMemory_6cbc {
  strings:
    $key_6cbc = { 3b ce [2] 09 ec [2] 0f d9 [2] 21 d9 [2] 1e c5 }

  condition:
    any of them
}