rule TTP_XOR_WriteProcessMemory_a58c {
  strings:
    $key_a58c = { f2 fe [2] c0 dc [2] c6 e9 [2] e8 e9 [2] d7 f5 }

  condition:
    any of them
}