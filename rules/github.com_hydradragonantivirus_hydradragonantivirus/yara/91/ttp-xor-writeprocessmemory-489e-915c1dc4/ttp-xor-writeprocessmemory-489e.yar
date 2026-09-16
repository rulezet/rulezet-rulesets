rule TTP_XOR_WriteProcessMemory_489e {
  strings:
    $key_489e = { 1f ec [2] 2d ce [2] 2b fb [2] 05 fb [2] 3a e7 }

  condition:
    any of them
}