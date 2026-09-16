rule TTP_XOR_WriteProcessMemory_5d9b {
  strings:
    $key_5d9b = { 0a e9 [2] 38 cb [2] 3e fe [2] 10 fe [2] 2f e2 }

  condition:
    any of them
}