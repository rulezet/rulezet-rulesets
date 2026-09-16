rule TTP_XOR_WriteProcessMemory_289e {
  strings:
    $key_289e = { 7f ec [2] 4d ce [2] 4b fb [2] 65 fb [2] 5a e7 }

  condition:
    any of them
}