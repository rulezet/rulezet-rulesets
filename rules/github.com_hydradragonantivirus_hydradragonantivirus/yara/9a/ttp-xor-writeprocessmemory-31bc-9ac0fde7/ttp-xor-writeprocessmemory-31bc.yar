rule TTP_XOR_WriteProcessMemory_31bc {
  strings:
    $key_31bc = { 66 ce [2] 54 ec [2] 52 d9 [2] 7c d9 [2] 43 c5 }

  condition:
    any of them
}