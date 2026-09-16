rule TTP_XOR_WriteProcessMemory_78bc {
  strings:
    $key_78bc = { 2f ce [2] 1d ec [2] 1b d9 [2] 35 d9 [2] 0a c5 }

  condition:
    any of them
}