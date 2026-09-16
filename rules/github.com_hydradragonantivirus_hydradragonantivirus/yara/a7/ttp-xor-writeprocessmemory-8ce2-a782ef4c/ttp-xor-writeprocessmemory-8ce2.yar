rule TTP_XOR_WriteProcessMemory_8ce2 {
  strings:
    $key_8ce2 = { db 90 [2] e9 b2 [2] ef 87 [2] c1 87 [2] fe 9b }

  condition:
    any of them
}