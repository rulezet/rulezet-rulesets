rule TTP_XOR_WriteProcessMemory_11bc {
  strings:
    $key_11bc = { 46 ce [2] 74 ec [2] 72 d9 [2] 5c d9 [2] 63 c5 }

  condition:
    any of them
}