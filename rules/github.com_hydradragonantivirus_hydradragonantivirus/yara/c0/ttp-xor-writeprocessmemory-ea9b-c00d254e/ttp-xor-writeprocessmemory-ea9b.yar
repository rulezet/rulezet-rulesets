rule TTP_XOR_WriteProcessMemory_ea9b {
  strings:
    $key_ea9b = { bd e9 [2] 8f cb [2] 89 fe [2] a7 fe [2] 98 e2 }

  condition:
    any of them
}