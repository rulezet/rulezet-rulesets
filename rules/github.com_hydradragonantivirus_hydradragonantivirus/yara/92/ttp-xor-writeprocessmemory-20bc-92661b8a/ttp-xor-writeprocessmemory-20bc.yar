rule TTP_XOR_WriteProcessMemory_20bc {
  strings:
    $key_20bc = { 77 ce [2] 45 ec [2] 43 d9 [2] 6d d9 [2] 52 c5 }

  condition:
    any of them
}