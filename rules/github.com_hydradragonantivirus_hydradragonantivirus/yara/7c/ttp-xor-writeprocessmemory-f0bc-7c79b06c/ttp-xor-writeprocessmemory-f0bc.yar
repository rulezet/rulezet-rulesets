rule TTP_XOR_WriteProcessMemory_f0bc {
  strings:
    $key_f0bc = { a7 ce [2] 95 ec [2] 93 d9 [2] bd d9 [2] 82 c5 }

  condition:
    any of them
}