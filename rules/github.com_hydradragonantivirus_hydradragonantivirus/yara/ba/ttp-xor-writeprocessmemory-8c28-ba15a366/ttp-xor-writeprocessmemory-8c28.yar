rule TTP_XOR_WriteProcessMemory_8c28 {
  strings:
    $key_8c28 = { db 5a [2] e9 78 [2] ef 4d [2] c1 4d [2] fe 51 }

  condition:
    any of them
}