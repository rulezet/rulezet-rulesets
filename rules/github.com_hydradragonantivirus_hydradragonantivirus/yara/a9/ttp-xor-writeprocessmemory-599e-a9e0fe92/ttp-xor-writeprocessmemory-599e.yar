rule TTP_XOR_WriteProcessMemory_599e {
  strings:
    $key_599e = { 0e ec [2] 3c ce [2] 3a fb [2] 14 fb [2] 2b e7 }

  condition:
    any of them
}