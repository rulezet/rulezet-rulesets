rule TTP_XOR_WriteProcessMemory_a79b {
  strings:
    $key_a79b = { f0 e9 [2] c2 cb [2] c4 fe [2] ea fe [2] d5 e2 }

  condition:
    any of them
}