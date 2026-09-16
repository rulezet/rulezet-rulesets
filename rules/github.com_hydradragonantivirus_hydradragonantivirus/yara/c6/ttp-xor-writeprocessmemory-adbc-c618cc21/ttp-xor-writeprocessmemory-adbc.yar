rule TTP_XOR_WriteProcessMemory_adbc {
  strings:
    $key_adbc = { fa ce [2] c8 ec [2] ce d9 [2] e0 d9 [2] df c5 }

  condition:
    any of them
}