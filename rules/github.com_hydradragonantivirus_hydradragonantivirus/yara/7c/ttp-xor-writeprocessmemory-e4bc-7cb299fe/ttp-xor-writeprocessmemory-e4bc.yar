rule TTP_XOR_WriteProcessMemory_e4bc {
  strings:
    $key_e4bc = { b3 ce [2] 81 ec [2] 87 d9 [2] a9 d9 [2] 96 c5 }

  condition:
    any of them
}