rule TTP_XOR_WriteProcessMemory_8e9e {
  strings:
    $key_8e9e = { d9 ec [2] eb ce [2] ed fb [2] c3 fb [2] fc e7 }

  condition:
    any of them
}