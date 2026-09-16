rule TTP_XOR_WriteProcessMemory_5981 {
  strings:
    $key_5981 = { 0e f3 [2] 3c d1 [2] 3a e4 [2] 14 e4 [2] 2b f8 }

  condition:
    any of them
}