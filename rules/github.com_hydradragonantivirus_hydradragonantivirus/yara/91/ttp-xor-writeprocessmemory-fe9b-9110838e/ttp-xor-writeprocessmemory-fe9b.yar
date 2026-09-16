rule TTP_XOR_WriteProcessMemory_fe9b {
  strings:
    $key_fe9b = { a9 e9 [2] 9b cb [2] 9d fe [2] b3 fe [2] 8c e2 }

  condition:
    any of them
}