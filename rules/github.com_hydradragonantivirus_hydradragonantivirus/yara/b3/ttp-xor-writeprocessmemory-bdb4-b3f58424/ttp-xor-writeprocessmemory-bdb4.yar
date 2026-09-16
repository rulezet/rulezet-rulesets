rule TTP_XOR_WriteProcessMemory_bdb4 {
  strings:
    $key_bdb4 = { ea c6 [2] d8 e4 [2] de d1 [2] f0 d1 [2] cf cd }

  condition:
    any of them
}