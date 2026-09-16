rule TTP_XOR_WriteProcessMemory_8c51 {
  strings:
    $key_8c51 = { db 23 [2] e9 01 [2] ef 34 [2] c1 34 [2] fe 28 }

  condition:
    any of them
}