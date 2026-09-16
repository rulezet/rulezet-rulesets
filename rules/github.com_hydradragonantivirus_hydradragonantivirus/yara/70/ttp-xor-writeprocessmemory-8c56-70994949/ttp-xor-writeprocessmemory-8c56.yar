rule TTP_XOR_WriteProcessMemory_8c56 {
  strings:
    $key_8c56 = { db 24 [2] e9 06 [2] ef 33 [2] c1 33 [2] fe 2f }

  condition:
    any of them
}