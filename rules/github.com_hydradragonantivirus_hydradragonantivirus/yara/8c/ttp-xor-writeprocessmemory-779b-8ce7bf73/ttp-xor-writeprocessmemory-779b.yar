rule TTP_XOR_WriteProcessMemory_779b {
  strings:
    $key_779b = { 20 e9 [2] 12 cb [2] 14 fe [2] 3a fe [2] 05 e2 }

  condition:
    any of them
}