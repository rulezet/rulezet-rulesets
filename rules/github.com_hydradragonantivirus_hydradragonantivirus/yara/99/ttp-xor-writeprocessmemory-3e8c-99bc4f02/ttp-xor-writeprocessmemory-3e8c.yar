rule TTP_XOR_WriteProcessMemory_3e8c {
  strings:
    $key_3e8c = { 69 fe [2] 5b dc [2] 5d e9 [2] 73 e9 [2] 4c f5 }

  condition:
    any of them
}