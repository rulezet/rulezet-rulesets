rule TTP_XOR_WriteProcessMemory_97bc {
  strings:
    $key_97bc = { c0 ce [2] f2 ec [2] f4 d9 [2] da d9 [2] e5 c5 }

  condition:
    any of them
}