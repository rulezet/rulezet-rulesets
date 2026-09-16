rule TTP_XOR_WriteProcessMemory_0cbc {
  strings:
    $key_0cbc = { 5b ce [2] 69 ec [2] 6f d9 [2] 41 d9 [2] 7e c5 }

  condition:
    any of them
}