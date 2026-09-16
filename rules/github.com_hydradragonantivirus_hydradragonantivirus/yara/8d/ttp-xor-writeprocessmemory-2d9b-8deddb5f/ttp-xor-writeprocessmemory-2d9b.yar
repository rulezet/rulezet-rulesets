rule TTP_XOR_WriteProcessMemory_2d9b {
  strings:
    $key_2d9b = { 7a e9 [2] 48 cb [2] 4e fe [2] 60 fe [2] 5f e2 }

  condition:
    any of them
}