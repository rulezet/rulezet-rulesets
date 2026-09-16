rule TTP_XOR_WriteProcessMemory_59bc {
  strings:
    $key_59bc = { 0e ce [2] 3c ec [2] 3a d9 [2] 14 d9 [2] 2b c5 }

  condition:
    any of them
}