rule TTP_XOR_WriteProcessMemory_5982 {
  strings:
    $key_5982 = { 0e f0 [2] 3c d2 [2] 3a e7 [2] 14 e7 [2] 2b fb }

  condition:
    any of them
}