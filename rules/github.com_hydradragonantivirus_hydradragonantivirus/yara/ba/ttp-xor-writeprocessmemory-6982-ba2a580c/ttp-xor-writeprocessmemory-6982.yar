rule TTP_XOR_WriteProcessMemory_6982 {
  strings:
    $key_6982 = { 3e f0 [2] 0c d2 [2] 0a e7 [2] 24 e7 [2] 1b fb }

  condition:
    any of them
}