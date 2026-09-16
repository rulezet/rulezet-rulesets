rule TTP_XOR_WriteProcessMemory_8c5f {
  strings:
    $key_8c5f = { db 2d [2] e9 0f [2] ef 3a [2] c1 3a [2] fe 26 }

  condition:
    any of them
}