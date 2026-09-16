rule TTP_XOR_WriteProcessMemory_6e8c {
  strings:
    $key_6e8c = { 39 fe [2] 0b dc [2] 0d e9 [2] 23 e9 [2] 1c f5 }

  condition:
    any of them
}