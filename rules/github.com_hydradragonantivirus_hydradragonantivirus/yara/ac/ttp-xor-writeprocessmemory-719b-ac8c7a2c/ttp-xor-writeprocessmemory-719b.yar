rule TTP_XOR_WriteProcessMemory_719b {
  strings:
    $key_719b = { 26 e9 [2] 14 cb [2] 12 fe [2] 3c fe [2] 03 e2 }

  condition:
    any of them
}