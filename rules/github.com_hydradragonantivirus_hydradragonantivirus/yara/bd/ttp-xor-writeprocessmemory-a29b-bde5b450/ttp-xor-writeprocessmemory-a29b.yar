rule TTP_XOR_WriteProcessMemory_a29b {
  strings:
    $key_a29b = { f5 e9 [2] c7 cb [2] c1 fe [2] ef fe [2] d0 e2 }

  condition:
    any of them
}