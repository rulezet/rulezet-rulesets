rule TTP_XOR_WriteProcessMemory_47bc {
  strings:
    $key_47bc = { 10 ce [2] 22 ec [2] 24 d9 [2] 0a d9 [2] 35 c5 }

  condition:
    any of them
}