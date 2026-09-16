rule TTP_XOR_WriteProcessMemory_b38c {
  strings:
    $key_b38c = { e4 fe [2] d6 dc [2] d0 e9 [2] fe e9 [2] c1 f5 }

  condition:
    any of them
}