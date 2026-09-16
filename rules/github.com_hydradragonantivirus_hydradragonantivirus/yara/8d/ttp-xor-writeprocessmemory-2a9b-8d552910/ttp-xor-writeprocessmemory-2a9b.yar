rule TTP_XOR_WriteProcessMemory_2a9b {
  strings:
    $key_2a9b = { 7d e9 [2] 4f cb [2] 49 fe [2] 67 fe [2] 58 e2 }

  condition:
    any of them
}