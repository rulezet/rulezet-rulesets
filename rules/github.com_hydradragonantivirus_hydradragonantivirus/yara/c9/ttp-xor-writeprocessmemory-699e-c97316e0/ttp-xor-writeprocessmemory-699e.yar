rule TTP_XOR_WriteProcessMemory_699e {
  strings:
    $key_699e = { 3e ec [2] 0c ce [2] 0a fb [2] 24 fb [2] 1b e7 }

  condition:
    any of them
}