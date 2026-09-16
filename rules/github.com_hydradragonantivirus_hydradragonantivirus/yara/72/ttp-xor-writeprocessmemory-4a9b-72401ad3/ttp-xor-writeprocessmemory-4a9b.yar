rule TTP_XOR_WriteProcessMemory_4a9b {
  strings:
    $key_4a9b = { 1d e9 [2] 2f cb [2] 29 fe [2] 07 fe [2] 38 e2 }

  condition:
    any of them
}