rule TTP_XOR_WriteProcessMemory_29bc {
  strings:
    $key_29bc = { 7e ce [2] 4c ec [2] 4a d9 [2] 64 d9 [2] 5b c5 }

  condition:
    any of them
}