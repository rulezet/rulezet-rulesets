rule TTP_XOR_WriteProcessMemory_279b {
  strings:
    $key_279b = { 70 e9 [2] 42 cb [2] 44 fe [2] 6a fe [2] 55 e2 }

  condition:
    any of them
}