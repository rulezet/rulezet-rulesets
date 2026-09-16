rule TTP_XOR_WriteProcessMemory_08bc {
  strings:
    $key_08bc = { 5f ce [2] 6d ec [2] 6b d9 [2] 45 d9 [2] 7a c5 }

  condition:
    any of them
}