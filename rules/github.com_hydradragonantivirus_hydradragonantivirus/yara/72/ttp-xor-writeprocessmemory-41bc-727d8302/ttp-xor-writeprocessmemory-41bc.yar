rule TTP_XOR_WriteProcessMemory_41bc {
  strings:
    $key_41bc = { 16 ce [2] 24 ec [2] 22 d9 [2] 0c d9 [2] 33 c5 }

  condition:
    any of them
}