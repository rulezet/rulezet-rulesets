rule TTP_XOR_WriteProcessMemory_73b1 {
  strings:
    $key_73b1 = { 24 c3 [2] 16 e1 [2] 10 d4 [2] 3e d4 [2] 01 c8 }

  condition:
    any of them
}