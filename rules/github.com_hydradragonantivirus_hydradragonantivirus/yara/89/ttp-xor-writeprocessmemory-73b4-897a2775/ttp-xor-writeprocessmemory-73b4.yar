rule TTP_XOR_WriteProcessMemory_73b4 {
  strings:
    $key_73b4 = { 24 c6 [2] 16 e4 [2] 10 d1 [2] 3e d1 [2] 01 cd }

  condition:
    any of them
}