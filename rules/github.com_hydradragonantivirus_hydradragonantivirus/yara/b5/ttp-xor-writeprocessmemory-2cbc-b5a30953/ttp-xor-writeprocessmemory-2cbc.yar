rule TTP_XOR_WriteProcessMemory_2cbc {
  strings:
    $key_2cbc = { 7b ce [2] 49 ec [2] 4f d9 [2] 61 d9 [2] 5e c5 }

  condition:
    any of them
}