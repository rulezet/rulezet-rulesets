rule TTP_XOR_WriteProcessMemory_f7bc {
  strings:
    $key_f7bc = { a0 ce [2] 92 ec [2] 94 d9 [2] ba d9 [2] 85 c5 }

  condition:
    any of them
}