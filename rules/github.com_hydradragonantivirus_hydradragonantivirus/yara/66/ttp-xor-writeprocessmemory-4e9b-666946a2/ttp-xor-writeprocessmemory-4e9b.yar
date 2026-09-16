rule TTP_XOR_WriteProcessMemory_4e9b {
  strings:
    $key_4e9b = { 19 e9 [2] 2b cb [2] 2d fe [2] 03 fe [2] 3c e2 }

  condition:
    any of them
}