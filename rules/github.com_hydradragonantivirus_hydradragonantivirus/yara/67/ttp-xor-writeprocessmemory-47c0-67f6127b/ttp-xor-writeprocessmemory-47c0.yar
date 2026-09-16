rule TTP_XOR_WriteProcessMemory_47c0 {
  strings:
    $key_47c0 = { 10 b2 [2] 22 90 [2] 24 a5 [2] 0a a5 [2] 35 b9 }

  condition:
    any of them
}