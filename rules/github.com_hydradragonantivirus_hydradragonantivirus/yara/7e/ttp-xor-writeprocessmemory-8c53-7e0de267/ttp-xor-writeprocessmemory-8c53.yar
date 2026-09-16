rule TTP_XOR_WriteProcessMemory_8c53 {
  strings:
    $key_8c53 = { db 21 [2] e9 03 [2] ef 36 [2] c1 36 [2] fe 2a }

  condition:
    any of them
}