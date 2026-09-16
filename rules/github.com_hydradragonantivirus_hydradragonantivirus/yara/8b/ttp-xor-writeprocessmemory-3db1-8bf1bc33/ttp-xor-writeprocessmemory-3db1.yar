rule TTP_XOR_WriteProcessMemory_3db1 {
  strings:
    $key_3db1 = { 6a c3 [2] 58 e1 [2] 5e d4 [2] 70 d4 [2] 4f c8 }

  condition:
    any of them
}