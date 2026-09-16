rule TTP_XOR_WriteProcessMemory_50bc {
  strings:
    $key_50bc = { 07 ce [2] 35 ec [2] 33 d9 [2] 1d d9 [2] 22 c5 }

  condition:
    any of them
}