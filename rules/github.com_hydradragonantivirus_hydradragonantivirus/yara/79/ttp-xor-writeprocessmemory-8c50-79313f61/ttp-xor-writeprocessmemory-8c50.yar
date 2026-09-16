rule TTP_XOR_WriteProcessMemory_8c50 {
  strings:
    $key_8c50 = { db 22 [2] e9 00 [2] ef 35 [2] c1 35 [2] fe 29 }

  condition:
    any of them
}