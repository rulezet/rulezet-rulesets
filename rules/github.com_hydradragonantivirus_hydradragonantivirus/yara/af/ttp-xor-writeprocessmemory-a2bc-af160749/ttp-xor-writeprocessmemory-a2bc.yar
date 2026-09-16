rule TTP_XOR_WriteProcessMemory_a2bc {
  strings:
    $key_a2bc = { f5 ce [2] c7 ec [2] c1 d9 [2] ef d9 [2] d0 c5 }

  condition:
    any of them
}