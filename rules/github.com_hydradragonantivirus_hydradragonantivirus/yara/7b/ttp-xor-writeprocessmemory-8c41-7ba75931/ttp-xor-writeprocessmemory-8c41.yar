rule TTP_XOR_WriteProcessMemory_8c41 {
  strings:
    $key_8c41 = { db 33 [2] e9 11 [2] ef 24 [2] c1 24 [2] fe 38 }

  condition:
    any of them
}