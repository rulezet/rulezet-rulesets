rule TTP_XOR_WriteProcessMemory_599b {
  strings:
    $key_599b = { 0e e9 [2] 3c cb [2] 3a fe [2] 14 fe [2] 2b e2 }

  condition:
    any of them
}