rule TTP_XOR_WriteProcessMemory_2db1 {
  strings:
    $key_2db1 = { 7a c3 [2] 48 e1 [2] 4e d4 [2] 60 d4 [2] 5f c8 }

  condition:
    any of them
}