rule TTP_XOR_WriteProcessMemory_389e {
  strings:
    $key_389e = { 6f ec [2] 5d ce [2] 5b fb [2] 75 fb [2] 4a e7 }

  condition:
    any of them
}