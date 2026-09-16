rule TTP_XOR_WriteProcessMemory_8c76 {
  strings:
    $key_8c76 = { db 04 [2] e9 26 [2] ef 13 [2] c1 13 [2] fe 0f }

  condition:
    any of them
}