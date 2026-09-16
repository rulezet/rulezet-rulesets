rule TTP_XOR_WriteProcessMemory_a08c {
  strings:
    $key_a08c = { f7 fe [2] c5 dc [2] c3 e9 [2] ed e9 [2] d2 f5 }

  condition:
    any of them
}