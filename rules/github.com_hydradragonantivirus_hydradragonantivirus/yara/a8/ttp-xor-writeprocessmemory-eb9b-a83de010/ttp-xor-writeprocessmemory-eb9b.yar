rule TTP_XOR_WriteProcessMemory_eb9b {
  strings:
    $key_eb9b = { bc e9 [2] 8e cb [2] 88 fe [2] a6 fe [2] 99 e2 }

  condition:
    any of them
}