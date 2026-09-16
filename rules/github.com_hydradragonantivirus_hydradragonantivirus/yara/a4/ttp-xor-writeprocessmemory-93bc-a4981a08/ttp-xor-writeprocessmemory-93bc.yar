rule TTP_XOR_WriteProcessMemory_93bc {
  strings:
    $key_93bc = { c4 ce [2] f6 ec [2] f0 d9 [2] de d9 [2] e1 c5 }

  condition:
    any of them
}