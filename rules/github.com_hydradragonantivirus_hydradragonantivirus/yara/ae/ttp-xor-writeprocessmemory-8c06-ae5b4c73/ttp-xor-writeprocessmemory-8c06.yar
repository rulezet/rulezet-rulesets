rule TTP_XOR_WriteProcessMemory_8c06 {
  strings:
    $key_8c06 = { db 74 [2] e9 56 [2] ef 63 [2] c1 63 [2] fe 7f }

  condition:
    any of them
}