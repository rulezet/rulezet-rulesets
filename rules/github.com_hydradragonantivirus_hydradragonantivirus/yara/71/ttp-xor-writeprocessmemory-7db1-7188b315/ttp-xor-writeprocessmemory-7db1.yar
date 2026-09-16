rule TTP_XOR_WriteProcessMemory_7db1 {
  strings:
    $key_7db1 = { 2a c3 [2] 18 e1 [2] 1e d4 [2] 30 d4 [2] 0f c8 }

  condition:
    any of them
}