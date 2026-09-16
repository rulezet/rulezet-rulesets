rule TTP_XOR_WriteProcessMemory_73b0 {
  strings:
    $key_73b0 = { 24 c2 [2] 16 e0 [2] 10 d5 [2] 3e d5 [2] 01 c9 }

  condition:
    any of them
}