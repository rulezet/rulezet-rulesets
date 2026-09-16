rule TTP_XOR_WriteProcessMemory_44bc {
  strings:
    $key_44bc = { 13 ce [2] 21 ec [2] 27 d9 [2] 09 d9 [2] 36 c5 }

  condition:
    any of them
}