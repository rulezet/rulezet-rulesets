rule TTP_XOR_WriteProcessMemory_8c8c {
  strings:
    $key_8c8c = { db fe [2] e9 dc [2] ef e9 [2] c1 e9 [2] fe f5 }

  condition:
    any of them
}