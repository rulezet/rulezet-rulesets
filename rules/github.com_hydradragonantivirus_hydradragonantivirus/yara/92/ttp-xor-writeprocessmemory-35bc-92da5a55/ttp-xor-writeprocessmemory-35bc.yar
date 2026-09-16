rule TTP_XOR_WriteProcessMemory_35bc {
  strings:
    $key_35bc = { 62 ce [2] 50 ec [2] 56 d9 [2] 78 d9 [2] 47 c5 }

  condition:
    any of them
}