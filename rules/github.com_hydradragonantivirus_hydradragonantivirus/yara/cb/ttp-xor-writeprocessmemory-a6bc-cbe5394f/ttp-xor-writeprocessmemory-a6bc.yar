rule TTP_XOR_WriteProcessMemory_a6bc {
  strings:
    $key_a6bc = { f1 ce [2] c3 ec [2] c5 d9 [2] eb d9 [2] d4 c5 }

  condition:
    any of them
}