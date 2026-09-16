rule TTP_XOR_WriteProcessMemory_52bc {
  strings:
    $key_52bc = { 05 ce [2] 37 ec [2] 31 d9 [2] 1f d9 [2] 20 c5 }

  condition:
    any of them
}