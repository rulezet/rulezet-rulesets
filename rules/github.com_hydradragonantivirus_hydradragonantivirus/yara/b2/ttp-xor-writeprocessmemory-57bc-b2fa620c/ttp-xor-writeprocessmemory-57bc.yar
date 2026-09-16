rule TTP_XOR_WriteProcessMemory_57bc {
  strings:
    $key_57bc = { 00 ce [2] 32 ec [2] 34 d9 [2] 1a d9 [2] 25 c5 }

  condition:
    any of them
}