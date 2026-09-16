rule TTP_XOR_WriteProcessMemory_38bc {
  strings:
    $key_38bc = { 6f ce [2] 5d ec [2] 5b d9 [2] 75 d9 [2] 4a c5 }

  condition:
    any of them
}