rule TTP_XOR_WriteProcessMemory_01bc {
  strings:
    $key_01bc = { 56 ce [2] 64 ec [2] 62 d9 [2] 4c d9 [2] 73 c5 }

  condition:
    any of them
}