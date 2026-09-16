rule TTP_XOR_WriteProcessMemory_68bc {
  strings:
    $key_68bc = { 3f ce [2] 0d ec [2] 0b d9 [2] 25 d9 [2] 1a c5 }

  condition:
    any of them
}