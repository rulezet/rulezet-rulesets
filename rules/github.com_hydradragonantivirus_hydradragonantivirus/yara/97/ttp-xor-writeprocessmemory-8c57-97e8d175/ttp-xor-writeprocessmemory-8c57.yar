rule TTP_XOR_WriteProcessMemory_8c57 {
  strings:
    $key_8c57 = { db 25 [2] e9 07 [2] ef 32 [2] c1 32 [2] fe 2e }

  condition:
    any of them
}