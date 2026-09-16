rule TTP_XOR_WriteProcessMemory_8c36 {
  strings:
    $key_8c36 = { db 44 [2] e9 66 [2] ef 53 [2] c1 53 [2] fe 4f }

  condition:
    any of them
}