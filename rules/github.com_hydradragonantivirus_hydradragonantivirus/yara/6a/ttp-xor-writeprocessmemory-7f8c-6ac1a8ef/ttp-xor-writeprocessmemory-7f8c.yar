rule TTP_XOR_WriteProcessMemory_7f8c {
  strings:
    $key_7f8c = { 28 fe [2] 1a dc [2] 1c e9 [2] 32 e9 [2] 0d f5 }

  condition:
    any of them
}