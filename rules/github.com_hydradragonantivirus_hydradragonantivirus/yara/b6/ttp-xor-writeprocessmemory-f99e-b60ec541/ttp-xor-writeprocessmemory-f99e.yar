rule TTP_XOR_WriteProcessMemory_f99e {
  strings:
    $key_f99e = { ae ec [2] 9c ce [2] 9a fb [2] b4 fb [2] 8b e7 }

  condition:
    any of them
}