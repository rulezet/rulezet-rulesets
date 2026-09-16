rule TTP_XOR_WriteProcessMemory_8ce1 {
  strings:
    $key_8ce1 = { db 93 [2] e9 b1 [2] ef 84 [2] c1 84 [2] fe 98 }

  condition:
    any of them
}