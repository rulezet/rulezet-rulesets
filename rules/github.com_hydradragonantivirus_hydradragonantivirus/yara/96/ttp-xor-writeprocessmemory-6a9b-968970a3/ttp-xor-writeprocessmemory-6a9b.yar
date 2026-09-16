rule TTP_XOR_WriteProcessMemory_6a9b {
  strings:
    $key_6a9b = { 3d e9 [2] 0f cb [2] 09 fe [2] 27 fe [2] 18 e2 }

  condition:
    any of them
}