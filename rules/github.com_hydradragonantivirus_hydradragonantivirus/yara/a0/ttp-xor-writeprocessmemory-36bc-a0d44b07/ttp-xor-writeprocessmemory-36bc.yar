rule TTP_XOR_WriteProcessMemory_36bc {
  strings:
    $key_36bc = { 61 ce [2] 53 ec [2] 55 d9 [2] 7b d9 [2] 44 c5 }

  condition:
    any of them
}