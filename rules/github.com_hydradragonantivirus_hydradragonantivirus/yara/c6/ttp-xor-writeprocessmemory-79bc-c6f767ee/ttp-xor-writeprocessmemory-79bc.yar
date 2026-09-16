rule TTP_XOR_WriteProcessMemory_79bc {
  strings:
    $key_79bc = { 2e ce [2] 1c ec [2] 1a d9 [2] 34 d9 [2] 0b c5 }

  condition:
    any of them
}