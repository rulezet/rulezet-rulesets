rule TTP_XOR_WriteProcessMemory_8c7f {
  strings:
    $key_8c7f = { db 0d [2] e9 2f [2] ef 1a [2] c1 1a [2] fe 06 }

  condition:
    any of them
}