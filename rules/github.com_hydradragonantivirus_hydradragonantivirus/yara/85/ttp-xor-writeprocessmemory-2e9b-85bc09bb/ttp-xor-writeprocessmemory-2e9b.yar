rule TTP_XOR_WriteProcessMemory_2e9b {
  strings:
    $key_2e9b = { 79 e9 [2] 4b cb [2] 4d fe [2] 63 fe [2] 5c e2 }

  condition:
    any of them
}