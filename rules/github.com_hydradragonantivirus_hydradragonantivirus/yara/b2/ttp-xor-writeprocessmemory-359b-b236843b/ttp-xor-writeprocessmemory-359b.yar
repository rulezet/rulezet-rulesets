rule TTP_XOR_WriteProcessMemory_359b {
  strings:
    $key_359b = { 62 e9 [2] 50 cb [2] 56 fe [2] 78 fe [2] 47 e2 }

  condition:
    any of them
}