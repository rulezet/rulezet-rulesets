rule TTP_XOR_WriteProcessMemory_6e9b {
  strings:
    $key_6e9b = { 39 e9 [2] 0b cb [2] 0d fe [2] 23 fe [2] 1c e2 }

  condition:
    any of them
}