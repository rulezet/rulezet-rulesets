rule TTP_XOR_WriteProcessMemory_a59b {
  strings:
    $key_a59b = { f2 e9 [2] c0 cb [2] c6 fe [2] e8 fe [2] d7 e2 }

  condition:
    any of them
}