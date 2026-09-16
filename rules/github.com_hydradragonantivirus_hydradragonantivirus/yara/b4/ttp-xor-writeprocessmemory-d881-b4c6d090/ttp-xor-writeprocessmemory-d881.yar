rule TTP_XOR_WriteProcessMemory_d881 {
  strings:
    $key_d881 = { 8f f3 [2] bd d1 [2] bb e4 [2] 95 e4 [2] aa f8 }

  condition:
    any of them
}