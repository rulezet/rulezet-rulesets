rule TTP_XOR_WriteProcessMemory_6f9b {
  strings:
    $key_6f9b = { 38 e9 [2] 0a cb [2] 0c fe [2] 22 fe [2] 1d e2 }

  condition:
    any of them
}