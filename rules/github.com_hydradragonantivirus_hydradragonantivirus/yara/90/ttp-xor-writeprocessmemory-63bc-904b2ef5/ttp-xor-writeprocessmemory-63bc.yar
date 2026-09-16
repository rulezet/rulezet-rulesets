rule TTP_XOR_WriteProcessMemory_63bc {
  strings:
    $key_63bc = { 34 ce [2] 06 ec [2] 00 d9 [2] 2e d9 [2] 11 c5 }

  condition:
    any of them
}