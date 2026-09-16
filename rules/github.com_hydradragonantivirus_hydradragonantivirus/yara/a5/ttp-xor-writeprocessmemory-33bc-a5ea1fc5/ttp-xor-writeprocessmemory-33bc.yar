rule TTP_XOR_WriteProcessMemory_33bc {
  strings:
    $key_33bc = { 64 ce [2] 56 ec [2] 50 d9 [2] 7e d9 [2] 41 c5 }

  condition:
    any of them
}