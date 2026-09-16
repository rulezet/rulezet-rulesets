rule TTP_XOR_WriteProcessMemory_23bc {
  strings:
    $key_23bc = { 74 ce [2] 46 ec [2] 40 d9 [2] 6e d9 [2] 51 c5 }

  condition:
    any of them
}