rule TTP_XOR_WriteProcessMemory_5e8c {
  strings:
    $key_5e8c = { 09 fe [2] 3b dc [2] 3d e9 [2] 13 e9 [2] 2c f5 }

  condition:
    any of them
}