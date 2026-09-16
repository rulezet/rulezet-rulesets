rule TTP_XOR_WriteProcessMemory_da9b {
  strings:
    $key_da9b = { 8d e9 [2] bf cb [2] b9 fe [2] 97 fe [2] a8 e2 }

  condition:
    any of them
}