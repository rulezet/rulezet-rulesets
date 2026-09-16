rule TTP_XOR_WriteProcessMemory_73bc {
  strings:
    $key_73bc = { 24 ce [2] 16 ec [2] 10 d9 [2] 3e d9 [2] 01 c5 }

  condition:
    any of them
}