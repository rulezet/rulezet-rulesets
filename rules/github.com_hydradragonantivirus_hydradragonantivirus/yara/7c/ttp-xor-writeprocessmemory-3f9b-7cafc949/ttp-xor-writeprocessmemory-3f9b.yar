rule TTP_XOR_WriteProcessMemory_3f9b {
  strings:
    $key_3f9b = { 68 e9 [2] 5a cb [2] 5c fe [2] 72 fe [2] 4d e2 }

  condition:
    any of them
}