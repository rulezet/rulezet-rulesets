rule TTP_XOR_WriteProcessMemory_8c3d {
  strings:
    $key_8c3d = { db 4f [2] e9 6d [2] ef 58 [2] c1 58 [2] fe 44 }

  condition:
    any of them
}