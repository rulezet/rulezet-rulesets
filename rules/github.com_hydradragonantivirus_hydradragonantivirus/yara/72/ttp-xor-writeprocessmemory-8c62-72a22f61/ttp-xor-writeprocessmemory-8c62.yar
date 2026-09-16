rule TTP_XOR_WriteProcessMemory_8c62 {
  strings:
    $key_8c62 = { db 10 [2] e9 32 [2] ef 07 [2] c1 07 [2] fe 1b }

  condition:
    any of them
}