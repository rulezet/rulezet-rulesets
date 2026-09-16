rule TTP_XOR_WriteProcessMemory_f79b {
  strings:
    $key_f79b = { a0 e9 [2] 92 cb [2] 94 fe [2] ba fe [2] 85 e2 }

  condition:
    any of them
}