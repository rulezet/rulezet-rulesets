rule TTP_XOR_WriteProcessMemory_8c40 {
  strings:
    $key_8c40 = { db 32 [2] e9 10 [2] ef 25 [2] c1 25 [2] fe 39 }

  condition:
    any of them
}