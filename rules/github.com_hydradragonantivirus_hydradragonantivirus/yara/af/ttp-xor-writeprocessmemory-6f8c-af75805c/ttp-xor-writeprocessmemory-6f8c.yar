rule TTP_XOR_WriteProcessMemory_6f8c {
  strings:
    $key_6f8c = { 38 fe [2] 0a dc [2] 0c e9 [2] 22 e9 [2] 1d f5 }

  condition:
    any of them
}