rule TTP_XOR_WriteProcessMemory_83bc {
  strings:
    $key_83bc = { d4 ce [2] e6 ec [2] e0 d9 [2] ce d9 [2] f1 c5 }

  condition:
    any of them
}