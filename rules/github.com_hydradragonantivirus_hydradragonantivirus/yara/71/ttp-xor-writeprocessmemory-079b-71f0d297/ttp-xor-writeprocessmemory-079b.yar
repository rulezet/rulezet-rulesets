rule TTP_XOR_WriteProcessMemory_079b {
  strings:
    $key_079b = { 50 e9 [2] 62 cb [2] 64 fe [2] 4a fe [2] 75 e2 }

  condition:
    any of them
}