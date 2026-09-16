rule TTP_XOR_WriteProcessMemory_8c32 {
  strings:
    $key_8c32 = { db 40 [2] e9 62 [2] ef 57 [2] c1 57 [2] fe 4b }

  condition:
    any of them
}