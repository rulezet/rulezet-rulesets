rule TTP_XOR_WriteProcessMemory_8c42 {
  strings:
    $key_8c42 = { db 30 [2] e9 12 [2] ef 27 [2] c1 27 [2] fe 3b }

  condition:
    any of them
}