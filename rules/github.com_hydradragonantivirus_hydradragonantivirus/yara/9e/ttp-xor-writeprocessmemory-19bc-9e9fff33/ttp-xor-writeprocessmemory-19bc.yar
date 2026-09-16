rule TTP_XOR_WriteProcessMemory_19bc {
  strings:
    $key_19bc = { 4e ce [2] 7c ec [2] 7a d9 [2] 54 d9 [2] 6b c5 }

  condition:
    any of them
}