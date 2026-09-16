rule TTP_XOR_WriteProcessMemory_aabc {
  strings:
    $key_aabc = { fd ce [2] cf ec [2] c9 d9 [2] e7 d9 [2] d8 c5 }

  condition:
    any of them
}