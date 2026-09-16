rule TTP_XOR_WriteProcessMemory_5a9b {
  strings:
    $key_5a9b = { 0d e9 [2] 3f cb [2] 39 fe [2] 17 fe [2] 28 e2 }

  condition:
    any of them
}