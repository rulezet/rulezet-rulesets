rule TTP_XOR_WriteProcessMemory_b18c {
  strings:
    $key_b18c = { e6 fe [2] d4 dc [2] d2 e9 [2] fc e9 [2] c3 f5 }

  condition:
    any of them
}