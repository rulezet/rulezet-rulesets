rule TTP_XOR_WriteProcessMemory_8c2d {
  strings:
    $key_8c2d = { db 5f [2] e9 7d [2] ef 48 [2] c1 48 [2] fe 54 }

  condition:
    any of them
}