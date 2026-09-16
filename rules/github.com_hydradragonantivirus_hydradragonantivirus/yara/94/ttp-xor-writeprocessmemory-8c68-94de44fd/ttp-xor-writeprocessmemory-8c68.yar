rule TTP_XOR_WriteProcessMemory_8c68 {
  strings:
    $key_8c68 = { db 1a [2] e9 38 [2] ef 0d [2] c1 0d [2] fe 11 }

  condition:
    any of them
}