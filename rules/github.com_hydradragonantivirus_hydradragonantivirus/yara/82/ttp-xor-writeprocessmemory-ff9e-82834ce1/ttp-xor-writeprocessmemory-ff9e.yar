rule TTP_XOR_WriteProcessMemory_ff9e {
  strings:
    $key_ff9e = { a8 ec [2] 9a ce [2] 9c fb [2] b2 fb [2] 8d e7 }

  condition:
    any of them
}