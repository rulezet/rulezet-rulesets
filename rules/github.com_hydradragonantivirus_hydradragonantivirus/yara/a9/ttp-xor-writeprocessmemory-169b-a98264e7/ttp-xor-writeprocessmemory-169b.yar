rule TTP_XOR_WriteProcessMemory_169b {
  strings:
    $key_169b = { 41 e9 [2] 73 cb [2] 75 fe [2] 5b fe [2] 64 e2 }

  condition:
    any of them
}