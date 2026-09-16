rule TTP_XOR_WriteProcessMemory_a5bc {
  strings:
    $key_a5bc = { f2 ce [2] c0 ec [2] c6 d9 [2] e8 d9 [2] d7 c5 }

  condition:
    any of them
}