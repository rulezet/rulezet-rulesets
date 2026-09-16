rule TTP_XOR_WriteProcessMemory_a38c {
  strings:
    $key_a38c = { f4 fe [2] c6 dc [2] c0 e9 [2] ee e9 [2] d1 f5 }

  condition:
    any of them
}