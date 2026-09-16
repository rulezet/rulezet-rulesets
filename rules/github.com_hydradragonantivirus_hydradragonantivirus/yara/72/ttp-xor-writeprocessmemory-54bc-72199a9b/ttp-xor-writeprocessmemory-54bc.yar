rule TTP_XOR_WriteProcessMemory_54bc {
  strings:
    $key_54bc = { 03 ce [2] 31 ec [2] 37 d9 [2] 19 d9 [2] 26 c5 }

  condition:
    any of them
}