rule TTP_XOR_WriteProcessMemory_53bc {
  strings:
    $key_53bc = { 04 ce [2] 36 ec [2] 30 d9 [2] 1e d9 [2] 21 c5 }

  condition:
    any of them
}