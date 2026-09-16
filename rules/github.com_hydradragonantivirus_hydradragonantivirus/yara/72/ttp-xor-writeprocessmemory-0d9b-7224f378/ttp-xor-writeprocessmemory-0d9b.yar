rule TTP_XOR_WriteProcessMemory_0d9b {
  strings:
    $key_0d9b = { 5a e9 [2] 68 cb [2] 6e fe [2] 40 fe [2] 7f e2 }

  condition:
    any of them
}