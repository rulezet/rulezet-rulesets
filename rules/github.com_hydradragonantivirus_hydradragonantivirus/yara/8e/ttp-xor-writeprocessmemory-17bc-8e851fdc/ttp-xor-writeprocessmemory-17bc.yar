rule TTP_XOR_WriteProcessMemory_17bc {
  strings:
    $key_17bc = { 40 ce [2] 72 ec [2] 74 d9 [2] 5a d9 [2] 65 c5 }

  condition:
    any of them
}