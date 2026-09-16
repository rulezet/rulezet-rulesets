rule TTP_XOR_WriteProcessMemory_2db4 {
  strings:
    $key_2db4 = { 7a c6 [2] 48 e4 [2] 4e d1 [2] 60 d1 [2] 5f cd }

  condition:
    any of them
}