rule TTP_XOR_WriteProcessMemory_95bc {
  strings:
    $key_95bc = { c2 ce [2] f0 ec [2] f6 d9 [2] d8 d9 [2] e7 c5 }

  condition:
    any of them
}