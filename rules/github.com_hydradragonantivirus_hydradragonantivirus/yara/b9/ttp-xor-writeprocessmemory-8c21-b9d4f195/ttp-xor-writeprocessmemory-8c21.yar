rule TTP_XOR_WriteProcessMemory_8c21 {
  strings:
    $key_8c21 = { db 53 [2] e9 71 [2] ef 44 [2] c1 44 [2] fe 58 }

  condition:
    any of them
}