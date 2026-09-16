rule TTP_XOR_WriteProcessMemory_479b {
  strings:
    $key_479b = { 10 e9 [2] 22 cb [2] 24 fe [2] 0a fe [2] 35 e2 }

  condition:
    any of them
}