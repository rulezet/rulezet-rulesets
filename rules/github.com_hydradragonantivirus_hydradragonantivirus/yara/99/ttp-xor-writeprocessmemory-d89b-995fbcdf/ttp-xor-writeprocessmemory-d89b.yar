rule TTP_XOR_WriteProcessMemory_d89b {
  strings:
    $key_d89b = { 8f e9 [2] bd cb [2] bb fe [2] 95 fe [2] aa e2 }

  condition:
    any of them
}