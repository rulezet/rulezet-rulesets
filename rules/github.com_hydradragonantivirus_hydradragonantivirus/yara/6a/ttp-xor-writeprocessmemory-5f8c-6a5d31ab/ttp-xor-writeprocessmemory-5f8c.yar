rule TTP_XOR_WriteProcessMemory_5f8c {
  strings:
    $key_5f8c = { 08 fe [2] 3a dc [2] 3c e9 [2] 12 e9 [2] 2d f5 }

  condition:
    any of them
}