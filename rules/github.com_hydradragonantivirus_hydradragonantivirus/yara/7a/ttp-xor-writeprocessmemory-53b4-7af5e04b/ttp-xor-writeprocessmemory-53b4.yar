rule TTP_XOR_WriteProcessMemory_53b4 {
  strings:
    $key_53b4 = { 04 c6 [2] 36 e4 [2] 30 d1 [2] 1e d1 [2] 21 cd }

  condition:
    any of them
}