rule TTP_XOR_WriteProcessMemory_8c4d {
  strings:
    $key_8c4d = { db 3f [2] e9 1d [2] ef 28 [2] c1 28 [2] fe 34 }

  condition:
    any of them
}