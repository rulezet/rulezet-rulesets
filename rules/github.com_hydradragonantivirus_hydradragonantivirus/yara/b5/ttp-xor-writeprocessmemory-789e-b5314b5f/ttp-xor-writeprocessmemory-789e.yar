rule TTP_XOR_WriteProcessMemory_789e {
  strings:
    $key_789e = { 2f ec [2] 1d ce [2] 1b fb [2] 35 fb [2] 0a e7 }

  condition:
    any of them
}