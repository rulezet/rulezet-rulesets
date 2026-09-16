rule TTP_XOR_WriteProcessMemory_7f9b {
  strings:
    $key_7f9b = { 28 e9 [2] 1a cb [2] 1c fe [2] 32 fe [2] 0d e2 }

  condition:
    any of them
}