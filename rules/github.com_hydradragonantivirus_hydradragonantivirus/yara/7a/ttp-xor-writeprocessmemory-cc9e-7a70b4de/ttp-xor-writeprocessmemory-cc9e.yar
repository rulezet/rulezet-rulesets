rule TTP_XOR_WriteProcessMemory_cc9e {
  strings:
    $key_cc9e = { 9b ec [2] a9 ce [2] af fb [2] 81 fb [2] be e7 }

  condition:
    any of them
}