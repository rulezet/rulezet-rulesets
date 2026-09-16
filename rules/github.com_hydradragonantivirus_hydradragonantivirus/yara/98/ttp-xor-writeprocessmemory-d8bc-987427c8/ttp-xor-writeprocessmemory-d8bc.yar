rule TTP_XOR_WriteProcessMemory_d8bc {
  strings:
    $key_d8bc = { 8f ce [2] bd ec [2] bb d9 [2] 95 d9 [2] aa c5 }

  condition:
    any of them
}