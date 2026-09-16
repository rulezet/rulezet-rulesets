rule TTP_XOR_WriteProcessMemory_8c12 {
  strings:
    $key_8c12 = { db 60 [2] e9 42 [2] ef 77 [2] c1 77 [2] fe 6b }

  condition:
    any of them
}