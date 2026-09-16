rule TTP_XOR_WriteProcessMemory_e5bc {
  strings:
    $key_e5bc = { b2 ce [2] 80 ec [2] 86 d9 [2] a8 d9 [2] 97 c5 }

  condition:
    any of them
}