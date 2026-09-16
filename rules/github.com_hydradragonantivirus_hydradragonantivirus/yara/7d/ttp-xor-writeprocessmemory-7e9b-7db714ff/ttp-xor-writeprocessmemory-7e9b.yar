rule TTP_XOR_WriteProcessMemory_7e9b {
  strings:
    $key_7e9b = { 29 e9 [2] 1b cb [2] 1d fe [2] 33 fe [2] 0c e2 }

  condition:
    any of them
}