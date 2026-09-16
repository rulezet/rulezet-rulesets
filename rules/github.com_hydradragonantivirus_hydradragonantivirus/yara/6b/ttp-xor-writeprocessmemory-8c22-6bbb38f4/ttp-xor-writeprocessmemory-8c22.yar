rule TTP_XOR_WriteProcessMemory_8c22 {
  strings:
    $key_8c22 = { db 50 [2] e9 72 [2] ef 47 [2] c1 47 [2] fe 5b }

  condition:
    any of them
}