rule TTP_XOR_WriteProcessMemory_8c7d {
  strings:
    $key_8c7d = { db 0f [2] e9 2d [2] ef 18 [2] c1 18 [2] fe 04 }

  condition:
    any of them
}