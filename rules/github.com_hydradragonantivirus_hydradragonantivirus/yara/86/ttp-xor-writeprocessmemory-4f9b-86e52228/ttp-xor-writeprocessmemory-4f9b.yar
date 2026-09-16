rule TTP_XOR_WriteProcessMemory_4f9b {
  strings:
    $key_4f9b = { 18 e9 [2] 2a cb [2] 2c fe [2] 02 fe [2] 3d e2 }

  condition:
    any of them
}