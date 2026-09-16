rule TTP_XOR_WriteProcessMemory_ccbc {
  strings:
    $key_ccbc = { 9b ce [2] a9 ec [2] af d9 [2] 81 d9 [2] be c5 }

  condition:
    any of them
}