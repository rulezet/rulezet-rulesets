rule TTP_XOR_WriteProcessMemory_b39b {
  strings:
    $key_b39b = { e4 e9 [2] d6 cb [2] d0 fe [2] fe fe [2] c1 e2 }

  condition:
    any of them
}