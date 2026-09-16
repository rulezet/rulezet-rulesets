rule TTP_XOR_WriteProcessMemory_a39b {
  strings:
    $key_a39b = { f4 e9 [2] c6 cb [2] c0 fe [2] ee fe [2] d1 e2 }

  condition:
    any of them
}