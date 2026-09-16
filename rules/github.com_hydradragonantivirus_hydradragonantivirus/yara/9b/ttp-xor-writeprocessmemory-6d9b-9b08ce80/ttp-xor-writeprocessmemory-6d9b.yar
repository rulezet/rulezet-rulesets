rule TTP_XOR_WriteProcessMemory_6d9b {
  strings:
    $key_6d9b = { 3a e9 [2] 08 cb [2] 0e fe [2] 20 fe [2] 1f e2 }

  condition:
    any of them
}