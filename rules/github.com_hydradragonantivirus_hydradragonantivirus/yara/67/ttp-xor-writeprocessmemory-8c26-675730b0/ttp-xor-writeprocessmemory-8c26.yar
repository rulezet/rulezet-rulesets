rule TTP_XOR_WriteProcessMemory_8c26 {
  strings:
    $key_8c26 = { db 54 [2] e9 76 [2] ef 43 [2] c1 43 [2] fe 5f }

  condition:
    any of them
}