rule TTP_XOR_WriteProcessMemory_5db1 {
  strings:
    $key_5db1 = { 0a c3 [2] 38 e1 [2] 3e d4 [2] 10 d4 [2] 2f c8 }

  condition:
    any of them
}