rule TTP_XOR_WriteProcessMemory_30bc {
  strings:
    $key_30bc = { 67 ce [2] 55 ec [2] 53 d9 [2] 7d d9 [2] 42 c5 }

  condition:
    any of them
}