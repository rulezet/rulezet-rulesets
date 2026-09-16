rule TTP_XOR_WriteProcessMemory_4e8c {
  strings:
    $key_4e8c = { 19 fe [2] 2b dc [2] 2d e9 [2] 03 e9 [2] 3c f5 }

  condition:
    any of them
}