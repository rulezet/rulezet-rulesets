rule TTP_XOR_WriteProcessMemory_28bc {
  strings:
    $key_28bc = { 7f ce [2] 4d ec [2] 4b d9 [2] 65 d9 [2] 5a c5 }

  condition:
    any of them
}