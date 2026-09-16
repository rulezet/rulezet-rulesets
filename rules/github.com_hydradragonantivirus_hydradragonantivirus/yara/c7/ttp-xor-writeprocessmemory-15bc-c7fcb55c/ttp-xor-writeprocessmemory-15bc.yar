rule TTP_XOR_WriteProcessMemory_15bc {
  strings:
    $key_15bc = { 42 ce [2] 70 ec [2] 76 d9 [2] 58 d9 [2] 67 c5 }

  condition:
    any of them
}