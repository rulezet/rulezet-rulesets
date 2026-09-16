rule TTP_XOR_WriteProcessMemory_81bc {
  strings:
    $key_81bc = { d6 ce [2] e4 ec [2] e2 d9 [2] cc d9 [2] f3 c5 }

  condition:
    any of them
}