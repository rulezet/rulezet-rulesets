rule TTP_XOR_WriteProcessMemory_0f9b {
  strings:
    $key_0f9b = { 58 e9 [2] 6a cb [2] 6c fe [2] 42 fe [2] 7d e2 }

  condition:
    any of them
}