rule TTP_XOR_WriteProcessMemory_1f9b {
  strings:
    $key_1f9b = { 48 e9 [2] 7a cb [2] 7c fe [2] 52 fe [2] 6d e2 }

  condition:
    any of them
}