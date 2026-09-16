rule TTP_XOR_WriteProcessMemory_1e9b {
  strings:
    $key_1e9b = { 49 e9 [2] 7b cb [2] 7d fe [2] 53 fe [2] 6c e2 }

  condition:
    any of them
}