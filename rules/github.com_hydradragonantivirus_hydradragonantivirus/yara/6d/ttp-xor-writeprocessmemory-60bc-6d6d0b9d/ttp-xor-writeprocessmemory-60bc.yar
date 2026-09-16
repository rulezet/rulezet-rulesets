rule TTP_XOR_WriteProcessMemory_60bc {
  strings:
    $key_60bc = { 37 ce [2] 05 ec [2] 03 d9 [2] 2d d9 [2] 12 c5 }

  condition:
    any of them
}