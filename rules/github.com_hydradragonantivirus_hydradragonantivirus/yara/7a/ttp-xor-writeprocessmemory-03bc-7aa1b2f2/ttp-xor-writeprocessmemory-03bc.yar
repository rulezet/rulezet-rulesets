rule TTP_XOR_WriteProcessMemory_03bc {
  strings:
    $key_03bc = { 54 ce [2] 66 ec [2] 60 d9 [2] 4e d9 [2] 71 c5 }

  condition:
    any of them
}