rule TTP_XOR_WriteProcessMemory_1e8c {
  strings:
    $key_1e8c = { 49 fe [2] 7b dc [2] 7d e9 [2] 53 e9 [2] 6c f5 }

  condition:
    any of them
}