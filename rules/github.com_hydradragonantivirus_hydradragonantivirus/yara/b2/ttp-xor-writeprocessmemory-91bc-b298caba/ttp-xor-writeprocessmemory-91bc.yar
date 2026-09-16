rule TTP_XOR_WriteProcessMemory_91bc {
  strings:
    $key_91bc = { c6 ce [2] f4 ec [2] f2 d9 [2] dc d9 [2] e3 c5 }

  condition:
    any of them
}